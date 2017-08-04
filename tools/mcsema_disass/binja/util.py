import binaryninja as binja
import logging
import magic


def load_binary(path):
    magic_type = magic.from_file(path)
    if 'ELF' in magic_type:
        bv_type = binja.BinaryViewType['ELF']
    elif 'PE32' in magic_type:
        bv_type = binja.BinaryViewType['PE']
    elif 'Mach-O' in magic_type:
        bv_type = binja.BinaryViewType['Mach-O']
    else:
        bv_type = binja.BinaryViewType['Raw']

        # Can't do anything with Raw type
        logging.error('Unknown binary type: "{}", exiting'.format(magic_type))
        exit(1)

    logging.debug('Loading binary in binja...')
    bv = bv_type.open(path)
    bv.update_analysis_and_wait()

    # NOTE: at the moment binja will not load a binary
    # that doesn't have an entry point
    if len(bv) == 0:
        logging.error('Binary could not be loaded in binja, is it linked?')
        exit(1)

    return bv
