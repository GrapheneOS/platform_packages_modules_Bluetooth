/*------------------------------------------------------------------------------
 *
 *  This file exposes a public interface to allow clients to invoke aptX
 *  encoding on 4 new PCM samples, generating 2 new codeword (one for the
 *  left channel and one for the right channel).
 *
 *----------------------------------------------------------------------------*/

#ifndef APTXBTENC_H
#define APTXBTENC_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _DLLEXPORT
#define APTXBTENCEXPORT __declspec(dllexport)
#else
#define APTXBTENCEXPORT
#endif

/* SizeofAptxbtenc returns the size (in byte) of the memory
 * allocation required to store the state of the encoder */
APTXBTENCEXPORT int SizeofAptxbtenc(void);

/* aptxbtenc_version can be used to extract the version number
 * of the aptX encoder */
APTXBTENCEXPORT const char* aptxbtenc_version(void);

/* aptxbtenc_init is used to initialise the encoder structure.
 * _state should be a pointer to the encoder structure (stereo).
 * endian represent the endianness of the output data
 * (0=little endian. Big endian otherwise)
 * The function returns 1 if an error occurred during the initialisation.
 * The function returns 0 if no error occurred during the initialisation. */
APTXBTENCEXPORT int aptxbtenc_init(void* _state, short endian);

/* aptxbtenc_setsync_mode is used to initialise the sync mode in the encoder state structure.
 * _state should be a pointer to the encoder structure (stereo, though strictly-speaking it is dual channel).
 * 'sync_mode' is an enumerated type  {stereo=0, dualmono=1, no_sync=2}
 * The function returns 0 if no error occurred during the initialisation. */
APTXBTENCEXPORT int aptxbtenc_setsync_mode(void* _state, int32_t sync_mode);

/* StereoEncode will take 8 audio samples (16-bit per sample)
 * and generate one 32-bit codeword with autosync inserted. */
APTXBTENCEXPORT int aptxbtenc_encodestereo(void* _state, void* _pcmL, void* _pcmR, void* _buffer);

#ifdef __cplusplus
} //  /extern "C"
#endif

#endif //APTXBTENC_H
