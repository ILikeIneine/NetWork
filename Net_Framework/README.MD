# Tiny Net Framework

## Message Structure

```text
-------------------------
| header |     body     |
-------------------------
```

Messages body is a stack-like structure, which is LIFO.

For example:

```text
// msg << info_1 << info_2 << info_3 << ...
```

reflected as:

```text
-------------------------------
| header | info_1 | info_2 |      <==== info_3
-------------------------------
          \--------- body ---------/
```

And the infos taking out from body must in reverse.

```text
// msg >> info_3 >> info_2 >> info_1;
```

There is a requirement that the infos pushing into message must be a standard layout.

## Connection Validation

We need to verify the validation of a connection started by a client.

Hence, before the business communication starting, there is a small procedure for checking.

```text
// Server: 
accept -> gen secret -> write_validation -> read_validation -> verify -> establish!

// client:
connect -> read_validation -> write_validation -> establish!
```

combined:

```text
[CLIENT]                [SERVER]
connect           ===>  accept
                        gen secret
read_validation   <===  write_validation
write_validation  ===>  read_validation 
establish!        <===  verify
                        establish!
```




