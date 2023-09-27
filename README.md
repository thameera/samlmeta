# SAML Meta

Reads a SAML Metadata document and prints the X.509 certificate and SSO URL.

## Usage

```sh
make

# Print the values
./samlmeta <PATH_TO_XML_FILE>

# Save the cert to file
./samlmeta <PATH_TO_XML_FILE> -w example.pem
 ```

## Installing

```
make install
```

Now you can invoke it with `samlmeta`.
