#include "backend.hpp"
#include "blrs/sampler.hpp"
#include <algorithm>
#include <exception>
#include <limits>
#include <stdexcept>
#include <utility>
extern "C" {
#include "lazer.h"
#include "blrs_callbacks.h"
}
#include "proof_params.h"

static_assert(RNG == RNG_AES256CTR,
              "The proof manifest requires the pinned AES256CTR challenge sampler");

namespace {
thread_local blrs::ExactSampler* current_sampler = nullptr;
thread_local std::exception_ptr sampler_failure;

struct Vector {
    polyvec_t value;
    explicit Vector(unsigned size) { polyvec_alloc(value, blrs_ring, size); polyvec_set_zero(value); }
    ~Vector() { polyvec_free(value); }
    Vector(const Vector&) = delete;
    Vector& operator=(const Vector&) = delete;
};
struct Polynomial {
    poly_t value;
    Polynomial() { poly_alloc(value, blrs_ring); poly_set_zero(value); }
    ~Polynomial() { poly_free(value); }
};
void import_poly(poly_ptr out, const blrs::QPoly& in) {
    std::array<std::int64_t,64> coeffs{};
    for (std::size_t i=0;i<64;++i) {
        if (in[i] >= blrs::proof_modulus) throw std::invalid_argument("Noncanonical proof-ring coefficient");
        coeffs[i] = static_cast<std::int64_t>(in[i]);
    }
    poly_set_coeffvec_i64(out, coeffs.data());
}
template<std::size_t N> void import_vector(Vector& out, const std::array<blrs::QPoly,N>& in) {
    for (std::size_t i=0;i<N;++i) import_poly(polyvec_get_elem(out.value, static_cast<unsigned>(i)), in[i]);
}
template<std::size_t N> void import_signed(Vector& out, const std::array<blrs::SignedPoly,N>& in) {
    for (std::size_t i=0;i<N;++i) poly_set_coeffvec_i64(polyvec_get_elem(out.value, static_cast<unsigned>(i)), in[i].data());
}
template<std::size_t N> void export_vector(std::array<blrs::QPoly,N>& out, Vector& in) {
    polyvec_mod(in.value,in.value); polyvec_redp(in.value,in.value);
    for (std::size_t i=0;i<N;++i) {
        blrs::SignedPoly coeffs{};
        poly_get_coeffvec_i64(coeffs.data(), polyvec_get_elem(in.value,static_cast<unsigned>(i)));
        for (std::size_t j=0;j<64;++j) out[i][j]=static_cast<std::uint64_t>(coeffs[j]);
    }
}
template<std::size_t N> void export_signed(std::array<blrs::SignedPoly,N>& out, Vector& in) {
    polyvec_fromcrt(in.value);
    for (std::size_t i=0;i<N;++i) poly_get_coeffvec_i64(out[i].data(),polyvec_get_elem(in.value,static_cast<unsigned>(i)));
}
struct Evaluations {
    std::vector<spolymat_ptr> quadratic;
    std::vector<spolyvec_ptr> linear;
    std::vector<poly_ptr> constant;
    explicit Evaluations(std::span<const blrs::SparseEvaluation> in, unsigned dimensions=80) {
        try {
            for (const auto& equation: in) {
                if(equation.quadratic.size()>dimensions*(dimensions+1)/2 || equation.linear.size()>dimensions) throw std::invalid_argument("Oversized sparse evaluation");
                quadratic.push_back(nullptr); linear.push_back(nullptr); constant.push_back(nullptr);
                const auto i=quadratic.size()-1;
                if (!equation.quadratic.empty()) {
                    std::vector<bool> seen(dimensions*dimensions);
                    quadratic[i]=new spolymat_struct{};
                    spolymat_alloc(quadratic[i],blrs_ring,dimensions,dimensions,static_cast<unsigned>(equation.quadratic.size()));
                    for(const auto& term:equation.quadratic) {
                        if(term.left>term.right || term.right>=dimensions) throw std::invalid_argument("Invalid quadratic variable index");
                        const auto position=term.left*dimensions+term.right;
                        if(seen[position]) throw std::invalid_argument("Duplicate quadratic variable pair");
                        seen[position]=true;
                        import_poly(spolymat_insert_elem(quadratic[i],static_cast<unsigned>(term.left),static_cast<unsigned>(term.right)),term.coefficient);
                    }
                    spolymat_sort(quadratic[i]);
                }
                if (!equation.linear.empty()) {
                    std::vector<bool> seen(dimensions);
                    linear[i]=new spolyvec_struct{};
                    spolyvec_alloc(linear[i],blrs_ring,dimensions,static_cast<unsigned>(equation.linear.size()));
                    for(const auto& term:equation.linear) {
                        if(term.index>=dimensions) throw std::invalid_argument("Invalid linear variable index");
                        if(seen[term.index]) throw std::invalid_argument("Duplicate linear variable index");
                        seen[term.index]=true;
                        import_poly(spolyvec_insert_elem(linear[i],static_cast<unsigned>(term.index)),term.coefficient);
                    }
                    spolyvec_sort(linear[i]);
                }
                constant[i]=new poly_struct{};
                poly_alloc(constant[i],blrs_ring); import_poly(constant[i],equation.constant);
            }
        } catch (...) { clear(); throw; }
    }
    static Evaluations scratch() {
        std::array<blrs::SparseEvaluation,5> empty{};
        Evaluations result(empty,90);
        for(std::size_t i=0;i<5;++i) {
            result.quadratic[i]=new spolymat_struct{};
            spolymat_alloc(result.quadratic[i],blrs_ring,90,90,4095);
            result.linear[i]=new spolyvec_struct{};
            spolyvec_alloc(result.linear[i],blrs_ring,90,90);
        }
        return result;
    }
    Evaluations(const Evaluations&)=delete;
    Evaluations& operator=(const Evaluations&)=delete;
    Evaluations(Evaluations&& other) noexcept : quadratic(std::move(other.quadratic)),linear(std::move(other.linear)),constant(std::move(other.constant)) {
        other.quadratic.clear();other.linear.clear();other.constant.clear();
    }
    ~Evaluations() { clear(); }
    void clear() noexcept {
        for(auto* p:quadratic) if(p) {spolymat_free(p);delete p;}
        for(auto* p:linear) if(p) {spolyvec_free(p);delete p;}
        for(auto* p:constant) if(p) {poly_free(p);delete p;}
        quadratic.clear();linear.clear();constant.clear();
    }
};
struct SamplerScope {
    explicit SamplerScope(blrs::ExactSampler& sampler) {
        if(current_sampler) throw std::logic_error("Nested backend sampling");
        sampler_failure=nullptr; current_sampler=&sampler;
    }
    ~SamplerScope(){current_sampler=nullptr;}
};
bool bounded(const blrs::BaseProof& proof, blrs::CoreProfile profile) {
    const auto check=[](const auto& polys, std::int64_t cap) {
        for(const auto& poly:polys) for(auto x:poly) if(x < -cap || x > cap) return false;
        return true;
    };
    if(!check(proof.z1,blrs::z1_coefficient_bound(profile)) || !check(proof.z21,5618953) || !check(proof.hint,1124199100721092LL)) return false;
    if(proof.c[32]!=0) return false;
    for(std::size_t i=0;i<32;++i) {
        if(proof.c[i]<-8 || proof.c[i]>8) return false;
        if(i && proof.c[64-i]!=-proof.c[i]) return false;
    }
    return true;
}
}

extern "C" int blrs_sample_vector(polyvec_t value, unsigned exponent) {
    try {
        if(!current_sampler) throw std::logic_error("Backend sampler missing");
        for(unsigned i=0;i<polyvec_get_nelems(value);++i) {
            blrs::SignedPoly coeffs{}; current_sampler->gaussian(coeffs,exponent);
            poly_set_coeffvec_i64(polyvec_get_elem(value,i),coeffs.data());
        }
        return 1;
    } catch(...) {sampler_failure=std::current_exception();return 0;}
}
extern "C" int blrs_reject_vector(intvec_t response,intvec_t shift,unsigned exponent,unsigned multiplier,int mode) {
    try {
        if(!current_sampler || intvec_get_nelems(response)!=intvec_get_nelems(shift) || (mode!=1 && mode!=2)) throw std::logic_error("Backend rejection sampler mismatch");
        std::vector<std::int64_t> z(intvec_get_nelems(response)),v(z.size());
        intvec_get_i64(z.data(),response);intvec_get_i64(v.data(),shift);
        const bool accepted=mode==1 ? current_sampler->ordinary_accept(z,v,exponent,multiplier) : current_sampler->bimodal_accept(z,v,exponent,multiplier);
        return accepted ? 0 : 1;
    } catch(...) {sampler_failure=std::current_exception();return 1;}
}

namespace blrs {
struct Backend::Impl {
    polymat_t A1,A2prime,Bprime;
    CoreProfile profile;
    lnp_quad_eval_params_srcptr params;
    explicit Impl(const ProofCrs& crs, CoreProfile selected) : profile(selected),
        params(selected == CoreProfile::Bimodal ? blrs_bimodal_params : blrs_params) {
        if(selected != CoreProfile::Ordinary && selected != CoreProfile::Bimodal) throw std::invalid_argument("Unknown core profile");
        if(crs.A1.size()!=20*23 || crs.A2prime.size()!=20*75 || crs.Bprime.size()!=23*75) throw std::invalid_argument("Incorrect proof CRS dimensions");
        for(const auto* matrix:{&crs.A1,&crs.A2prime,&crs.Bprime}) for(const auto& poly:*matrix) for(auto x:poly) if(x>=proof_modulus) throw std::invalid_argument("Noncanonical proof CRS");
        lazer_init();
        polymat_alloc(A1,blrs_ring,20,23);polymat_alloc(A2prime,blrs_ring,20,75);polymat_alloc(Bprime,blrs_ring,23,75);
        const auto fill=[](polymat_ptr matrix,const std::vector<QPoly>& polys,unsigned columns) {
            for(std::size_t i=0;i<polys.size();++i) import_poly(polymat_get_elem(matrix,static_cast<unsigned>(i)/columns,static_cast<unsigned>(i)%columns),polys[i]);
        };
        fill(A1,crs.A1,23);fill(A2prime,crs.A2prime,75);fill(Bprime,crs.Bprime,75);
    }
    ~Impl(){polymat_free(A1);polymat_free(A2prime);polymat_free(Bprime);}
};
Backend::Backend(const ProofCrs& crs, CoreProfile profile):impl_(std::make_unique<Impl>(crs,profile)){}
Backend::~Backend()=default;
CoreProfile Backend::profile() const { return impl_->profile; }
void Backend::commit(Opening& opening) const {
    for(const auto& p:opening.rho) for(auto x:p) if(x < -1 || x>1) throw std::invalid_argument("Commitment randomness must be ternary");
    Vector s1(23),message(23),rho(95),tA1(20),tA2(20),tB(23);
    import_vector(s1,opening.small);import_vector(message,opening.message);import_signed(rho,opening.rho);
    abdlop_commit(tA1.value,tA2.value,tB.value,s1.value,message.value,rho.value,impl_->A1,impl_->A2prime,impl_->Bprime,impl_->params->quad_eval);
    export_vector(opening.tA1,tA1);export_vector(opening.tA2,tA2);export_vector(opening.tB,tB);
}
std::optional<BaseProof> Backend::prove_one_attempt(Opening& opening,std::span<const SparseEvaluation> evaluations,Seed hash,const Seed& seed,ExactSampler& sampler) const {
    if(evaluations.size()!=1133) throw std::invalid_argument("Expected 1133 scalar evaluations");
    Vector s1(23),message(23),rho(95),tA2(20),tB(23),h(5),z1(23),z21(75),hint(20);
    Polynomial c;
    import_vector(s1,opening.small);import_vector(message,opening.message);import_signed(rho,opening.rho);
    import_vector(tA2,opening.tA2);import_vector(tB,opening.tB);
    Evaluations input(evaluations),scratch=Evaluations::scratch();
    SamplerScope scope(sampler);
    const auto accepted=lnp_quad_eval_prove(hash.data(),tB.value,h.value,c.value,z1.value,z21.value,hint.value,s1.value,message.value,rho.value,tA2.value,impl_->A1,impl_->A2prime,impl_->Bprime,scratch.quadratic.data(),scratch.linear.data(),0,input.quadratic.data(),input.linear.data(),input.constant.data(),1133,seed.data(),impl_->params);
    if(sampler_failure) std::rethrow_exception(sampler_failure);
    if(!accepted) return std::nullopt;
    BaseProof proof;proof.tA1=opening.tA1;
    export_vector(proof.tB,tB);export_vector(proof.base_h,h);
    poly_get_coeffvec_i64(proof.c.data(),c.value);
    export_signed(proof.z1,z1);export_signed(proof.z21,z21);export_signed(proof.hint,hint);
    return proof;
}
bool Backend::verify(const BaseProof& proof,std::span<const SparseEvaluation> evaluations,Seed hash) const {
    if(evaluations.size()!=1133 || !bounded(proof,impl_->profile)) return false;
    try {
        Vector tA1(20),tB(23),h(5),z1(23),z21(75),hint(20);Polynomial c;
        import_vector(tA1,proof.tA1);import_vector(tB,proof.tB);import_vector(h,proof.base_h);
        import_signed(z1,proof.z1);import_signed(z21,proof.z21);import_signed(hint,proof.hint);
        poly_set_coeffvec_i64(c.value,proof.c.data());
        Evaluations input(evaluations),scratch=Evaluations::scratch();
        return lnp_quad_eval_verify(hash.data(),h.value,c.value,z1.value,z21.value,hint.value,tA1.value,tB.value,impl_->A1,impl_->A2prime,impl_->Bprime,scratch.quadratic.data(),scratch.linear.data(),scratch.constant.data(),0,input.quadratic.data(),input.linear.data(),input.constant.data(),1133,impl_->params)==1;
    } catch(const std::invalid_argument&) {return false;}
}
}
