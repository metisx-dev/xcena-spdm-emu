/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "library/spdm_transport_xcena_lib.h"
#include "library/spdm_secured_message_lib.h"
#include "hal/library/debuglib.h"

#define LIBSPDM_PCI_DOE_ALIGNMENT 4
#define LIBSPDM_PCI_DOE_SEQUENCE_NUMBER_COUNT 0
#define LIBSPDM_PCI_DOE_MAX_RANDOM_NUMBER_COUNT 0

/**
 * Get sequence number in an SPDM secure message.
 *
 * This value is transport layer specific.
 *
 * @param sequence_number        The current sequence number used to encode or decode message.
 * @param sequence_number_buffer  A buffer to hold the sequence number output used in the secured message.
 *                             The size in byte of the output buffer shall be 8.
 *
 * @return size in byte of the sequence_number_buffer.
 *        It shall be no greater than 8.
 *        0 means no sequence number is required.
 **/
static uint8_t libspdm_pci_doe_get_sequence_number_custom(uint64_t sequence_number,
                                                          uint8_t *sequence_number_buffer)
{
    return LIBSPDM_PCI_DOE_SEQUENCE_NUMBER_COUNT;
}

/**
 * Return max random number count in an SPDM secure message.
 *
 * This value is transport layer specific.
 *
 * @return Max random number count in an SPDM secured message.
 *        0 means no random number is required.
 **/
static uint32_t libspdm_pci_doe_get_max_random_number_count_custom(void)
{
    return LIBSPDM_PCI_DOE_MAX_RANDOM_NUMBER_COUNT;
}

/**
 * This function translates the negotiated secured_message_version to a DSP0277 version.
 *
 * @param  secured_message_version  The version specified in binding specification and
 *                                  negotiated in KEY_EXCHANGE/KEY_EXCHANGE_RSP.
 *
 * @return The DSP0277 version specified in binding specification,
 *         which is bound to secured_message_version.
 */
static spdm_version_number_t libspdm_pci_doe_get_secured_spdm_version_custom(
    spdm_version_number_t secured_message_version)
{
    /* PCI-SIG uses DSP0277 version */
    return secured_message_version;
}

/**
 * Encode a normal message or secured message to a transport message.
 *
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a source buffer to store the message.
 *                                     For normal message, it will point to the acquired sender buffer.
 *                                     For secured message, it will point to the scratch buffer in spdm_context.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a destination buffer to store the transport message.
 *                                     For normal message or secured message, it will point to acquired sender buffer.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 **/
libspdm_return_t xcena_encode_message(const uint32_t *session_id, size_t message_size,
                                      const void *message,
                                      size_t *transport_message_size,
                                      void **transport_message);

/**
 * Decode a transport message to a normal message or secured message.
 *
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If *session_id is NULL, it is a normal message.
 *                                     If *session_id is NOT NULL, it is a secured message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a source buffer to store the transport message.
 *                                     For normal message or secured message, it will point to acquired receiver buffer.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a destination buffer to store the message.
 *                                     For normal message, it will point to the original receiver buffer.
 *                                     For secured message, it will point to the scratch buffer in spdm_context.
 * @retval LIBSPDM_STATUS_SUCCESS               The message is encoded successfully.
 * @retval RETURN_INVALID_PARAMETER     The message is NULL or the message_size is zero.
 **/
libspdm_return_t xcena_decode_message(uint32_t **session_id,
                                      size_t transport_message_size,
                                      const void *transport_message,
                                      size_t *message_size, void **message);

/**
 * Encode an SPDM from a transport layer message.
 *
 * Only for normal SPDM message, it adds the transport layer wrapper.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If *session_id is NULL, it is a normal message.
 *                                     If *session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  is_requester                  Indicates if it is a requester message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a source buffer to store the transport message.
 *                                     For normal message or secured message, it shall point to acquired receiver buffer.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a destination buffer to store the message.
 *                                     On input, it shall be msg_buf_ptr from receiver buffer.
 *                                     On output, for normal message, it will point to the original receiver buffer.
 *                                     On output, for secured message, it will point to the scratch buffer in spdm_context.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The message is decoded successfully.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP       The message is invalid.
 **/
libspdm_return_t spdm_transport_xcena_encode_message(
    void *spdm_context, const uint32_t *session_id, bool is_app_message,
    bool is_requester, size_t message_size, void *message,
    size_t *transport_message_size, void **transport_message)
{
    libspdm_return_t status;
    uint8_t *secured_message; 
    size_t secured_message_size;
    libspdm_secured_message_callbacks_t spdm_secured_message_callbacks;
    void *secured_message_context;
    size_t sec_trans_header_size;

    spdm_secured_message_callbacks.version =
        LIBSPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    spdm_secured_message_callbacks.get_sequence_number =
        libspdm_pci_doe_get_sequence_number_custom;
    spdm_secured_message_callbacks.get_max_random_number_count =
        libspdm_pci_doe_get_max_random_number_count_custom;
    spdm_secured_message_callbacks.get_secured_spdm_version =
        libspdm_pci_doe_get_secured_spdm_version_custom;

    if (is_app_message) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (session_id != NULL) {
        secured_message_context =
            libspdm_get_secured_message_context_via_session_id(
                spdm_context, *session_id);
        if (secured_message_context == NULL) {
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }

        /* message to secured message*/
        sec_trans_header_size = spdm_transport_xcena_get_header_size(spdm_context);
        secured_message = (uint8_t *)*transport_message + sec_trans_header_size;
        secured_message_size = *transport_message_size - sec_trans_header_size;
        status = libspdm_encode_secured_message(
            secured_message_context, *session_id, is_requester,
            message_size, message, &secured_message_size,
            secured_message, &spdm_secured_message_callbacks);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "libspdm_encode_secured_message - %xu\n", status));
            return status;
        }

        status = xcena_encode_message(session_id, secured_message_size, secured_message,
                                      transport_message_size,
                                      transport_message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "transport_encode_message - %p\n",
                        status));
            return status;
        }
    }
    else
    {
    /* normal message */
        status = xcena_encode_message(NULL, message_size, message,
                                      transport_message_size,
                                      transport_message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "transport_encode_message - %p\n",
                        status));
            return status;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Decode an SPDM from a transport layer message.
 *
 * Only for normal SPDM message, it removes the transport layer wrapper.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates if it is a secured message protected via SPDM session.
 *                                     If *session_id is NULL, it is a normal message.
 *                                     If *session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  is_requester                  Indicates if it is a requester message.
 * @param  transport_message_size         size in bytes of the transport message data buffer.
 * @param  transport_message             A pointer to a source buffer to store the transport message.
 *                                     For normal message or secured message, it shall point to acquired receiver buffer.
 * @param  message_size                  size in bytes of the message data buffer.
 * @param  message                      A pointer to a destination buffer to store the message.
 *                                     On input, it shall be msg_buf_ptr from receiver buffer.
 *                                     On output, for normal message, it will point to the original receiver buffer.
 *                                     On output, for secured message, it will point to the scratch buffer in spdm_context.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The message is decoded successfully.
 * @retval LIBSPDM_STATUS_UNSUPPORTED_CAP       The message is invalid.
 **/
libspdm_return_t spdm_transport_xcena_decode_message(
    void *spdm_context, uint32_t **session_id,
    bool *is_app_message, bool is_requester,
    size_t transport_message_size, void *transport_message,
    size_t *message_size, void **message)
{

    libspdm_return_t status;
    uint32_t *secured_message_session_id;
    void *secured_message;
    size_t secured_message_size;
    libspdm_secured_message_callbacks_t spdm_secured_message_callbacks;
    void *secured_message_context;
    libspdm_error_struct_t spdm_error;

    spdm_error.error_code = 0;
    spdm_error.session_id = 0;
    libspdm_set_last_spdm_error_struct(spdm_context, &spdm_error);

    spdm_secured_message_callbacks.version =
        LIBSPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    spdm_secured_message_callbacks.get_sequence_number =
        libspdm_pci_doe_get_sequence_number_custom;
    spdm_secured_message_callbacks.get_max_random_number_count =
        libspdm_pci_doe_get_max_random_number_count_custom;
    spdm_secured_message_callbacks.get_secured_spdm_version =
        libspdm_pci_doe_get_secured_spdm_version_custom;

    if ((session_id == NULL) || (is_app_message == NULL)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    *is_app_message = false;

    /* get non-secured message*/
    status = xcena_decode_message(&secured_message_session_id,
                                 transport_message_size,
                                 transport_message,
                                 &secured_message_size, &secured_message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "transport_decode_message - %p\n",
                    status));
        return status;
    }
    
    if (secured_message_session_id != NULL) {
        *session_id = secured_message_session_id;

        secured_message_context =
            libspdm_get_secured_message_context_via_session_id(
                spdm_context, *secured_message_session_id);
        if (secured_message_context == NULL) {
            spdm_error.error_code = SPDM_ERROR_CODE_INVALID_SESSION;
            spdm_error.session_id = *secured_message_session_id;
            libspdm_set_last_spdm_error_struct(spdm_context,
                                               &spdm_error);
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }

        /* Secured message to message*/
        status = libspdm_decode_secured_message(
            secured_message_context, *secured_message_session_id,
            is_requester, secured_message_size, secured_message,
            message_size, message,
            &spdm_secured_message_callbacks);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "libspdm_decode_secured_message - %xu\n", status));
            libspdm_secured_message_get_last_spdm_error_struct(
                secured_message_context, &spdm_error);
            libspdm_set_last_spdm_error_struct(spdm_context,
                                               &spdm_error);
            return status;
        }
        return LIBSPDM_STATUS_SUCCESS;
    }
    else
    {
        *message = secured_message;
        *message_size = secured_message_size;
    }

    *session_id = NULL;
    *is_app_message = false;
    return LIBSPDM_STATUS_SUCCESS;
}
