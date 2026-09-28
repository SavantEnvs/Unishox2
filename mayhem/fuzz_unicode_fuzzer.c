/*
 * mayhem/fuzz_unicode_fuzzer.c — libFuzzer harness ported (verbatim, modulo the include path)
 * from the original mayhemheroes integration: mayhem-fuzz/unicode-fuzzer.c @
 * https://github.com/mayhemheroes/Unishox2 (target "unicode_fuzzer", run 2). Reconstructed here
 * rather than reusing the current v2 decompress-only harness because the bug this backport
 * reproduces (CWE-125 out-of-bounds-read in matchOccurance(), reached via unishox2_compress())
 * lives in the COMPRESS path, which the current v2 harness never calls — it only exercises
 * unishox2_decompress(). The first input byte selects compress (even) or decompress (odd); the
 * remaining bytes are the payload, matching the original harness's input framing exactly so the
 * downloaded mayhemheroes corpus replays unchanged.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../unishox2.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size > 2) {
        char* input = (char*) malloc(Size - 1);
        memcpy(input, Data + 1, Size - 1);
        char* output = (char*) malloc(Size * 16);

        switch (Data[0] % 2) {
            case 0:
                unishox2_compress(input, Size - 1, output, Size * 8, USX_HCODES_DFLT, USX_HCODE_LENS_DFLT, USX_FREQ_SEQ_TXT, USX_TEMPLATES);
                break;
            case 1:
                unishox2_decompress(input, Size - 1, output, Size * 8, USX_HCODES_DFLT, USX_HCODE_LENS_DFLT, USX_FREQ_SEQ_TXT, USX_TEMPLATES);
                break;
        }

        free(input);
        free(output);
    }
  return 0;
}
