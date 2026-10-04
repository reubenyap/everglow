// Component benchmark only: this is neither a signature implementation nor key generation.
// Deterministic mt19937 inputs are for repeatability, never for production secrets.
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <stdexcept>

namespace {
constexpr std::size_t degree = 64;
constexpr std::size_t rows = 4; // Two public-key polynomials and two tag polynomials.
constexpr std::size_t max_width = 24;
constexpr std::int64_t modulus = 65437;
using Polynomial = std::array<std::uint16_t, degree>;
using Matrix = std::array<std::array<Polynomial, max_width>, rows>;
using Secret = std::array<std::array<std::uint8_t, degree>, max_width>;
using Result = std::array<Polynomial, rows>;

std::uint16_t reduce(std::int64_t value)
{
    const auto residue = value % modulus;
    return static_cast<std::uint16_t>(residue < 0 ? residue + modulus : residue);
}

Result evaluate(const Matrix& matrix, const Secret& secret, std::size_t width)
{
    Result result{};
    // ponytail: schoolbook binary convolution, replace with an optimized kernel only
    // when measuring a complete implementation with the same arithmetic contract.
    for (std::size_t row = 0; row < rows; ++row) {
        std::array<std::int64_t, degree> sum{};
        for (std::size_t column = 0; column < width; ++column) {
            for (std::size_t j = 0; j < degree; ++j) {
                if (secret[column][j] == 0) {
                    continue;
                }
                for (std::size_t i = 0; i < degree - j; ++i) {
                    sum[i + j] += matrix[row][column][i];
                }
                for (std::size_t i = degree - j; i < degree; ++i) {
                    sum[i + j - degree] -= matrix[row][column][i];
                }
            }
        }
        for (std::size_t k = 0; k < degree; ++k) {
            result[row][k] = reduce(sum[k]);
        }
    }
    return result;
}

Result reference(const Matrix& matrix, const Secret& secret, std::size_t width)
{
    Result result{};
    for (std::size_t row = 0; row < rows; ++row) {
        for (std::size_t k = 0; k < degree; ++k) {
            std::int64_t sum = 0;
            for (std::size_t column = 0; column < width; ++column) {
                for (std::size_t i = 0; i < degree; ++i) {
                    const auto j = (k + degree - i) % degree;
                    const auto product = static_cast<std::int64_t>(matrix[row][column][i])
                        * secret[column][j];
                    sum += i <= k ? product : -product;
                }
            }
            result[row][k] = reduce(sum);
        }
    }
    return result;
}

std::uint64_t checksum(const Result& result)
{
    std::uint64_t sum = 0;
    for (std::size_t row = 0; row < rows; ++row) {
        for (std::size_t k = 0; k < degree; ++k) {
            sum += static_cast<std::uint64_t>(result[row][k]) * (row * degree + k + 1);
        }
    }
    return sum;
}

void self_check(const Matrix& matrix, const std::array<Secret, 16>& secrets)
{
    for (std::size_t width = 16; width <= max_width; ++width) {
        if (std::any_of(secrets.begin(), secrets.end(), [&](const auto& secret) {
                return evaluate(matrix, secret, width) != reference(matrix, secret, width);
            })) {
            throw std::runtime_error("convolution disagrees with dense reference");
        }
    }
    Matrix boundary{};
    Secret secret{};
    boundary[0][0][degree - 1] = 1;
    secret[0][1] = 1;
    if (evaluate(boundary, secret, 1)[0][0] != modulus - 1) {
        throw std::runtime_error("X^64 must reduce to -1");
    }
    for (auto& row : boundary) {
        for (auto& polynomial : row) {
            polynomial.fill(static_cast<std::uint16_t>(modulus - 1));
        }
    }
    for (auto& polynomial : secret) {
        polynomial.fill(1);
    }
    if (evaluate(boundary, secret, max_width) != reference(boundary, secret, max_width)
        || reduce(-modulus) != 0 || reduce(modulus) != 0 || reduce(-1) != modulus - 1) {
        throw std::runtime_error("modular boundary check failed");
    }
}
} // namespace

int main() try
{
    Matrix matrix{};
    std::array<Secret, 16> secrets{};
    std::mt19937 generator(0x424c4f4dU);
    std::uniform_int_distribution<unsigned int> coefficient(0, modulus - 1);
    std::uniform_int_distribution<unsigned int> bit(0, 1);
    for (auto& row : matrix) {
        for (auto& polynomial : row) {
            std::generate(polynomial.begin(), polynomial.end(), [&] {
                return static_cast<std::uint16_t>(coefficient(generator));
            });
        }
    }
    for (auto& secret : secrets) {
        for (auto& polynomial : secret) {
            std::generate(polynomial.begin(), polynomial.end(), [&] {
                return static_cast<std::uint8_t>(bit(generator));
            });
        }
    }
    self_check(matrix, secrets);
    constexpr std::size_t batch = 128;
    volatile std::uint64_t sink = 0;
    std::cout << "width,secret_bytes,witness_coefficients,matrix_bytes,key_bytes,tag_bytes,"
                 "mean_coefficient_additions,median_ns_combined_evaluation,checksum\n";
    std::cout << std::fixed << std::setprecision(2);
    for (std::size_t width = 16; width <= max_width; ++width) {
        std::uint64_t sum = 0;
        std::uint64_t ones = 0;
        for (const auto& secret : secrets) {
            sum += checksum(evaluate(matrix, secret, width));
            for (std::size_t column = 0; column < width; ++column) {
                ones = std::accumulate(secret[column].begin(), secret[column].end(), ones);
            }
        }
        std::array<double, 9> times{};
        for (auto& elapsed : times) {
            const auto start = std::chrono::steady_clock::now();
            for (std::size_t i = 0; i < batch; ++i) {
                sum += checksum(evaluate(matrix, secrets[i % secrets.size()], width));
            }
            const auto stop = std::chrono::steady_clock::now();
            elapsed = std::chrono::duration<double, std::nano>(stop - start).count() / batch;
            sink = sum;
        }
        std::sort(times.begin(), times.end());
        std::cout << width << ',' << width * degree / 8 << ',' << width * degree << ','
                  << rows * width * degree * sizeof(std::uint16_t) << ','
                  << 2 * degree * sizeof(std::uint16_t) << ','
                  << 2 * degree * sizeof(std::uint16_t) << ','
                  << static_cast<double>(ones * rows * degree) / secrets.size() << ','
                  << times[times.size() / 2] << ',' << sink << '\n';
    }
}
catch (const std::exception& error)
{
    std::cerr << error.what() << '\n';
    return 1;
}
