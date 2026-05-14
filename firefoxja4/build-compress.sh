clang++ -std=c++17 \
  tls-client-compress.cc \
  -I/home/user/UNI/TFG/bsslclient/boringssl/include \
  /home/user/UNI/TFG/bsslclient/boringssl/build/libssl.a \
  /home/user/UNI/TFG/bsslclient/boringssl/build/libcrypto.a \
  -lz -lbrotlienc -lbrotlidec -lzstd \
  -lpthread -ldl -lm \
  -o tls-client
