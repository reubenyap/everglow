#ifndef BLRS_CALLBACKS_H
#define BLRS_CALLBACKS_H
/* Research sampler callbacks used only by the fixed benchmark adapter. */
#ifdef __cplusplus
extern "C" {
#endif
int blrs_sample_vector(polyvec_t value, unsigned int log2stdev);
int blrs_reject_vector(intvec_t response, intvec_t shift,
                       unsigned int log2stdev, unsigned int multiplier,
                       int mode);
#ifdef __cplusplus
}
#endif
#endif
