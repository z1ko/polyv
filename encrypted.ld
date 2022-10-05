SECTIONS {
    
    /**
    /* Section holding the encrypted payload
    /* defines two symbols for the begin and the end
    /* of the encrypted data:
    /*      
    /*      __load_start_encrypted
    /*      __load_stop_encrypted
    */
    OVERLAY : {
        .etext
        {
            /* ELF specification */
            . = ALIGN(4); 
            *(.etext)

        }
    }

    /* Section holding the decryption key */
    .ekey : { *(.ekey) }

} INSERT AFTER .text;

