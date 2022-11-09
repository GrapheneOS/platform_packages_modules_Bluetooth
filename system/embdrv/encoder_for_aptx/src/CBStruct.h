/*------------------------------------------------------------------------------
 *
 *  Structure required to implement a circular buffer.
 *
 *----------------------------------------------------------------------------*/

#ifndef CBSTRUCT_H
#define CBSTRUCT_H
#ifdef _GCC
  #pragma GCC visibility push(hidden)
#endif


typedef struct circularBuffer_t
{
   /* Buffer storage */
   int32_t buffer[48];
   /* Pointer to current buffer location */
   uint32_t pointer;
   /* Modulo length of circular buffer */
   uint32_t modulo;
}circularBuffer;


#ifdef _GCC
  #pragma GCC visibility pop
#endif
#endif //CBSTRUCT_H