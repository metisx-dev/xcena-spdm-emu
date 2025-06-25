/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_device_validator_sample.h"

void *m_spdm_context;
void *m_scratch_buffer;
SOCKET m_socket;

extern FILE *m_log_file;

bool communicate_platform_data(SOCKET socket, uint32_t command,
                               const uint8_t *send_buffer, size_t bytes_to_send,
                               uint32_t *response,
                               size_t *bytes_to_receive,
                               uint8_t *receive_buffer)
{
    bool result;

    result =
        send_platform_data(socket, command, send_buffer, bytes_to_send);
    if (!result) {
        printf("send_platform_data Error - %x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        return result;
    }

    result = receive_platform_data(socket, response, receive_buffer,
                                   bytes_to_receive);
    if (!result) {
        printf("receive_platform_data Error - %x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        return result;
    }
    return result;
}

libspdm_return_t spdm_device_send_message(void *spdm_context,
                                          size_t request_size, const void *request,
                                          uint64_t timeout)
{
    bool result;

    result = send_platform_data(m_socket, SOCKET_SPDM_COMMAND_NORMAL,
                                request, (uint32_t)request_size);
    if (!result) {
        printf("send_platform_data Error - %x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        return LIBSPDM_STATUS_SEND_FAIL;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdm_device_receive_message(void *spdm_context,
                                             size_t *response_size,
                                             void **response,
                                             uint64_t timeout)
{
    bool result;
    uint32_t command;

    result = receive_platform_data(m_socket, &command, *response,
                                   response_size);
    if (!result) {
        printf("receive_platform_data Error - %x\n",
#ifdef _MSC_VER
               WSAGetLastError()
#else
               errno
#endif
               );
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

#define SPDM_CMD "cmtest data"
#define SPDM_PAYLOAD_PATH "/workspace/spdm_payload/"
#define SPDM_FLOW_ID 100
#define SPDM_SEND_PAYLOAD "spdm-send-"
#define SPDM_RECV_PAYLOAD "spdm-recv-"

static int spdm_cmd_idx = 0;
extern FILE *m_log_file;

static void print_payload(const char *payload, size_t size, bool is_send)
{
    const uint32_t header_size = 12;

    if (size < header_size) {
        return;
    }

    uint8_t* actual_payload = (uint8_t*)payload + header_size;
    uint32_t actual_size = size - header_size;

    fprintf(m_log_file, "%s:\n", is_send ? "send-transport" : "recv-transport");
    for (size_t i = 0; i < actual_size; i++) {
        fprintf(m_log_file, "%02X ", actual_payload[i]);
        if (i % 16 == 15) {
            fprintf(m_log_file, "\n");
        }
    }
    fprintf(m_log_file, "\n");
}

libspdm_return_t spdm_xcena_send_message(void *spdm_context,
                                         size_t request_size, const void *request,
                                         uint64_t timeout)
{
    char cmd[1024];

    print_payload(request, request_size, true);

    sprintf(cmd, "%s%s%d", SPDM_PAYLOAD_PATH, SPDM_SEND_PAYLOAD, spdm_cmd_idx);

    FILE* fp = fopen(cmd, "wb");  // 바이너리 모드로 열기
    if (!fp) {
        return LIBSPDM_STATUS_SEND_FAIL;
    }

    fwrite(request, 1, request_size, fp);
    fclose(fp);

    system("sleep 0.001");

    sprintf(cmd, "%s -f%d %s%s%d -t 1000000000 > %s%s%d", 
            SPDM_CMD, SPDM_FLOW_ID,
            SPDM_PAYLOAD_PATH, SPDM_SEND_PAYLOAD, spdm_cmd_idx,
            SPDM_PAYLOAD_PATH, SPDM_RECV_PAYLOAD, spdm_cmd_idx);
    system(cmd);

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdm_xcena_receive_message(void *spdm_context,
                                            size_t *response_size,
                                            void **response,
                                            uint64_t timeout)
{
    char filename[1024];

    sprintf(filename, "%s%s%d", SPDM_PAYLOAD_PATH, SPDM_RECV_PAYLOAD, spdm_cmd_idx);

    int tries = 1000 * 10;  // 100ms 간격으로 체크
    FILE* fp = NULL;
    
    while (tries > 0) {
        fp = fopen(filename, "rb");
        if (fp) {
            break;
        }
        system("sleep 0.001");
        tries--;
    }
    
    if (NULL == fp) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    spdm_cmd_idx++;

    fseek(fp, 0, SEEK_END);
    *response_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fread(*response, 1, *response_size, fp) != *response_size) {
        fclose(fp);
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    fclose(fp);

    print_payload(*response, *response_size, false);

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Send and receive an DOE message
 *
 * @param request                       the PCI DOE request message, start from pci_doe_data_object_header_t.
 * @param request_size                  size in bytes of request.
 * @param response                      the PCI DOE response message, start from pci_doe_data_object_header_t.
 * @param response_size                 size in bytes of response.
 *
 * @retval LIBSPDM_STATUS_SUCCESS               The request is sent and response is received.
 * @return ERROR                        The response is not received correctly.
 **/
libspdm_return_t pci_doe_send_receive_data(const void *pci_doe_context,
                                           size_t request_size, const void *request,
                                           size_t *response_size, void *response)
{
    bool result;
    uint32_t response_code;

    result = communicate_platform_data(
        m_socket, SOCKET_SPDM_COMMAND_NORMAL,
        request, request_size,
        &response_code, response_size,
        response);
    if (!result) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

void *spdm_client_init(void)
{
    void *spdm_context;
    size_t scratch_buffer_size;

    printf("context_size - 0x%x\n", (uint32_t)libspdm_get_context_size());

    m_spdm_context = (void *)malloc(libspdm_get_context_size());
    if (m_spdm_context == NULL) {
        return NULL;
    }
    spdm_context = m_spdm_context;
    libspdm_init_context(spdm_context);

    libspdm_register_device_io_func(spdm_context, spdm_xcena_send_message,
                                    spdm_xcena_receive_message);

    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
        libspdm_register_transport_layer_func(
            spdm_context,
            LIBSPDM_MAX_SPDM_MSG_SIZE,
            LIBSPDM_TRANSPORT_HEADER_SIZE,
            LIBSPDM_TRANSPORT_TAIL_SIZE,
            libspdm_transport_mctp_encode_message,
            libspdm_transport_mctp_decode_message);
    } else if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
        libspdm_register_transport_layer_func(
            spdm_context,
            LIBSPDM_MAX_SPDM_MSG_SIZE,
            LIBSPDM_TRANSPORT_HEADER_SIZE,
            LIBSPDM_TRANSPORT_TAIL_SIZE,
            libspdm_transport_pci_doe_encode_message,
            libspdm_transport_pci_doe_decode_message);
    } else if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_NONE) {
        libspdm_register_transport_layer_func(
            spdm_context,
            LIBSPDM_MAX_SPDM_MSG_SIZE,
            0,
            0,
            spdm_transport_none_encode_message,
            spdm_transport_none_decode_message);
    } else if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_XCENA) {
        libspdm_register_transport_layer_func(
            spdm_context,
            LIBSPDM_MAX_SPDM_MSG_SIZE,
            LIBSPDM_TRANSPORT_HEADER_SIZE,
            LIBSPDM_TRANSPORT_TAIL_SIZE,
            spdm_transport_xcena_encode_message,
            spdm_transport_xcena_decode_message);
    } else {
        free(m_spdm_context);
        m_spdm_context = NULL;
        return NULL;
    }

    libspdm_register_device_buffer_func(spdm_context,
                                        LIBSPDM_SENDER_BUFFER_SIZE,
                                        LIBSPDM_RECEIVER_BUFFER_SIZE,
                                        spdm_device_acquire_sender_buffer,
                                        spdm_device_release_sender_buffer,
                                        spdm_device_acquire_receiver_buffer,
                                        spdm_device_release_receiver_buffer);

    scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(m_spdm_context);
    m_scratch_buffer = (void *)malloc(scratch_buffer_size);
    if (m_scratch_buffer == NULL) {
        free(m_spdm_context);
        m_spdm_context = NULL;
        return NULL;
    }
    libspdm_set_scratch_buffer (spdm_context, m_scratch_buffer, scratch_buffer_size);

    return m_spdm_context;
}
