#include "AptxParameters.h"
#include "SubbandFunctionsCommon.h"
#include "SubbandFunctions.h"


/* This function carries out all subband processing (common to both encode and decode). */
void processSubband_HD(const int32_t qCode, const int32_t ditherVal, Subband_data* SubbandDataPt, IQuantiser_data* iqDataPt)
{
   /* Inverse quantisation */
   invertQuantisation(qCode, ditherVal, iqDataPt);

   /* Predictor pole coefficient update */
   updatePredictorPoleCoefficients(iqDataPt->invQ, SubbandDataPt->m_predData.m_zeroVal, &SubbandDataPt->m_PoleCoeffData);

   /* Predictor filtering */
   performPredictionFiltering(iqDataPt->invQ, SubbandDataPt);
}

/* processSubband_HDLL is used for the LL subband only. */
void processSubband_HDLL(const int32_t qCode, const int32_t ditherVal, Subband_data* SubbandDataPt, IQuantiser_data* iqDataPt)
{
   /* Inverse quantisation */
   invertQuantisation(qCode, ditherVal, iqDataPt);

   /* Predictor pole coefficient update */
   updatePredictorPoleCoefficients(iqDataPt->invQ, SubbandDataPt->m_predData.m_zeroVal, &SubbandDataPt->m_PoleCoeffData);

   /* Predictor filtering */
   performPredictionFilteringLL(iqDataPt->invQ, SubbandDataPt);
}

/* processSubband_HDLL is used for the HL subband only. */
void processSubband_HDHL(const int32_t qCode, const int32_t ditherVal, Subband_data* SubbandDataPt, IQuantiser_data* iqDataPt)
{
   /* Inverse quantisation */
   invertQuantisationHL(qCode, ditherVal, iqDataPt);

   /* Predictor pole coefficient update */
   updatePredictorPoleCoefficients(iqDataPt->invQ, SubbandDataPt->m_predData.m_zeroVal, &SubbandDataPt->m_PoleCoeffData);

   /* Predictor filtering */
   performPredictionFilteringHL(iqDataPt->invQ, SubbandDataPt);
}
