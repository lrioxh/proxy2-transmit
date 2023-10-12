#include <stdio.h>

void size_t_to_binary(size_t num, unsigned char *buffer, size_t buffer_length) {
    for (int i = buffer_length - 1; i >= 0; i--) {
        buffer[i] = num & 0xFF; // 取最低8位
        num >>= 8; // 向右移动8位
    }
}

void print_hex(unsigned char *buffer, size_t buffer_length) {
    for (size_t i = 0; i < buffer_length; i++) {
        printf("%02X ", buffer[i]); // %02X 以十六进制打印，且至少两位
    }
    printf("\n");
}

int main() {
    size_t num = 1002; // 一个示例 size_t 数字
    size_t buffer_length = 3; // 缓冲区长度与size_t大小相同

    unsigned char buffer[buffer_length];

    size_t_to_binary(num, buffer, buffer_length);

    printf("Hexadecimal representation of %zu:\n", num);
    print_hex(buffer, buffer_length);

    return 0;
}
