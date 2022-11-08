/*------------------------------------------------------------------------------
 *
 *  Function to calculate a quantised representation of an input
 *  difference signal, based on additional dither values and step-size inputs.
 *
 *-----------------------------------------------------------------------------*/

#ifndef QUANTISER_H
#define QUANTISER_H
#ifdef _GCC
  #pragma GCC visibility push(hidden)
#endif


#include "AptxParameters.h"


void quantiseDifferenceLL(const int32_t diffSignal, const int32_t ditherVal, const int32_t delta, Quantiser_data* qdata_pt);
void quantiseDifferenceHL(const int32_t diffSignal, const int32_t ditherVal, const int32_t delta, Quantiser_data* qdata_pt);
void quantiseDifferenceLH(const int32_t diffSignal, const int32_t ditherVal, const int32_t delta, Quantiser_data* qdata_pt);
void quantiseDifferenceHH(const int32_t diffSignal, const int32_t ditherVal, const int32_t delta, Quantiser_data* qdata_pt);


#ifdef _GCC
  #pragma GCC visibility pop
#endif
#endif //QUANTISER_H
