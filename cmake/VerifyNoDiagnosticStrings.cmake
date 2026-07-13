if(NOT DEFINED BINARY OR NOT EXISTS "${BINARY}")
    message(FATAL_ERROR "Error-mode test binary not found: ${BINARY}")
endif()

foreach(BURNERNET_FORBIDDEN_STRING
        DisabledBackend
        VerifyGeneric
        HardenedResponseVerifierRequired
        HardenedPersistentMtlsForbidden)
    file(STRINGS
        "${BINARY}"
        BURNERNET_MATCHING_STRINGS
        REGEX "${BURNERNET_FORBIDDEN_STRING}")
    if(BURNERNET_MATCHING_STRINGS)
        message(FATAL_ERROR
            "Diagnostic string '${BURNERNET_FORBIDDEN_STRING}' leaked into ${BINARY}")
    endif()
endforeach()
