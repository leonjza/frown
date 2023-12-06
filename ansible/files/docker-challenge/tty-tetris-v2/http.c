#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "http.h"

static size_t write_callback(void *contents, size_t size, size_t nmemb, char **response) {
    memcpy(*response, contents, 80);

    return size * nmemb;
}

void http_post(const char *url, const char *post_data, char *response) {
    CURL *curl = curl_easy_init();
    if (!curl) return;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        response = NULL;
    }

    curl_easy_cleanup(curl);
}
