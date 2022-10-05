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
        .encrypted
        {
            /* ELF specification */
            . = ALIGN(4); 
            *(.encrypted)

        } =0xDEADBEEF
    }

} INSERT AFTER .text;

