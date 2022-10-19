/*-----------------------------------------------------------------------------
 *
 *  This file exposes a public interface to allow clients to invoke aptX HD
 *  encoding on 4 new PCM samples, generating 2 new codeword (one for the
 *  left channel and one for the right channel).
 *
 *----------------------------------------------------------------------------*/

#ifndef APTXHDBTENC_H
#define APTXHDBTENC_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _DLLEXPORT
#define APTXHDBTENCEXPORT __declspec(dllexport)
#else
#define APTXHDBTENCEXPORT
#endif


/* SizeofAptxhdbtenc returns the size (in byte) of the memory
 * allocation required to store the state of the encoder */
APTXHDBTENCEXPORT int SizeofAptxhdbtenc (void);

/* aptxhdbtenc_version can be used to extract the version number
 * of the aptX HD encoder */
APTXHDBTENCEXPORT const char* aptxhdbtenc_version(void);

/* aptxhdbtenc_init is used to initialise the encoder structure.
 * _state should be a pointer to the encoder structure (stereo).
 * endian represent the endianness of the output data
 * (0=little endian. Big endian otherwise)
 * The function returns 1 if an error occurred during the initialisation.
 * The function returns 0 if no error occurred during the initialisation. */
APTXHDBTENCEXPORT int aptxhdbtenc_init(void* _state, short endian);

/* StereoEncode will take 8 audio samples (24-bit per sample)
 * and generate one 24-bit codeword with autosync inserted.
 * The bitstream is compatible with be BC05 implementation. */
APTXHDBTENCEXPORT int aptxhdbtenc_encodestereo(void* _state, void* _pcmL, void* _pcmR, void* _buffer);


#ifdef __cplusplus
} //  /extern "C"
#endif

#endif //APTXHDBTENC_H
