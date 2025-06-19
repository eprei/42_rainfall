#include <stdlib.h>
#include <string.h>

class N {
public:
    char annotation[100];
    int amount;

    N(int amount) : amount(amount) {}

    void setAnnotation(char * str) {
          size_t str_len;

          str_len = strlen(str);
          memcpy(annotation, str, str_len);
          return;
    }

    N operator+(N const & other) {
        return N(this->amount + other.amount);
    }

    N operator-(N const & other) {
        return N(this->amount - other.amount);
    }
};

int main(int argc, char **argv)
{
    if (argc < 2) {
        exit(1);
    }

    N *first_instance = new N(5);
    N *second_instance = new N(6);

    first_instance->setAnnotation(argv[1]);

    (*second_instance) + (*first_instance);

    return 0;
}