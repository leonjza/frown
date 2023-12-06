#ifndef TTY_TETRIS_HTTP_H
#define TTY_TETRIS_HTTP_H

static size_t write_callback(void *contents, size_t size, size_t nmemb, char **response);

void http_post(const char *url, const char *post_data, char *response);

#endif //TTY_TETRIS_HTTP_H
