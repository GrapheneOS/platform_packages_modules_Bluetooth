#include "AptxParameters.h"
#include "SubbandFunctionsCommon.h"
#include "SubbandFunctions.h"


/*  This function carries out all subband processing (common to both encode and decode). */
void processSubband(const int32_t qCode, const int32_t ditherVal, Subband_data* SubbandDataPt, IQuantiser_data* iqDataPt)
{
   /* Inverse quantisation */
   invertQuantisation(qCode, ditherVal, iqDataPt);

   /* Predictor pole coefficient update */
   updatePredictorPoleCoefficients(iqDataPt->invQ, SubbandDataPt->m_predData.m_zeroVal, &SubbandDataPt->m_PoleCoeffData);

   /* Predictor filtering */
   performPredictionFiltering(iqDataPt->invQ, SubbandDataPt);
}

/* processSubbandLL is used for the LL subband only. */
void processSubbandLL(const int32_t qCode, const int32_t ditherVal, Subband_data* SubbandDataPt, IQuantiser_data* iqDataPt)
{
   /* Inverse quantisation */
   invertQuantisation(qCode, ditherVal, iqDataPt);

   /* Predictor pole coefficient update */
   updatePredictorPoleCoefficients(iqDataPt->invQ, SubbandDataPt->m_predData.m_zeroVal, &SubbandDataPt->m_PoleCoeffData);

   /* Predictor filtering */
   performPredictionFilteringLL(iqDataPt->invQ, SubbandDataPt);
}

/* processSubbandHL is used for the HL subband only. */
void processSubbandHL(const int32_t qCode, const int32_t ditherVal, Subband_data* SubbandDataPt, IQuantiser_data* iqDataPt)
{
   /* Inverse quantisation */
   invertQuantisationHL(qCode, ditherVal, iqDataPt);

   /* Predictor pole coefficient update */
   updatePredictorPoleCoefficients(iqDataPt->invQ, SubbandDataPt->m_predData.m_zeroVal, &SubbandDataPt->m_PoleCoeffData);

   /* Predictor filtering */
   performPredictionFilteringHL(iqDataPt->invQ, SubbandDataPt);
}
