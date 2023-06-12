# Task 2 

# Part 1

## Password Generator

### Without key, password of a given length (default: 8) is randomly generated from a set of characters (small lateral ASCII, big lateral ASCII, digit)

```
CLI interface can support next commands:
- n: Set length of password and generate random password from set {small lateral ASCII, big lateral ASCII,
digit}
- t: Set template for generate passwords
- f: Getting list of patterns from file and generate for each random password
- c: number of passwords
-vvv: Verbose mode (-v |-vv |-vvv )
-h: help
-S: character set
-p: Randomly permute characters of password
```

## Placeholders:

| Placeholder | Type  | Character Set |
|---|----|-----|
|d            | Digit | 0123456789    |
| l | Lower-Case Letter | abcdefghijklmnopqrstuvwxyz |
| L | Mixed-Case Letter | ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz |
| u | Upper-Case Letter | ABCDEFGHIJKLMNOPQRSTUVWXYZ |
| p | Punctuation       |      ,.;:                  |
| \ | Escape (Fixed Char) | Use following character as is. |
| {n} | Escape (Repeat) | Repeat the previous placeholder n times. |
| [...] | Custom Char | Set Define a custom character set.  |


The placeholder marked with a backslash (\\) has a special function as an escape character. When a backslash is followed by another character, that character is directly included in the generated password. To include a backslash itself in a specific position within the password, you need to write two backslashes (\\).

By using the {n} code, you can specify the number of times the preceding placeholder should occur. The { } operator duplicates the placeholders without generating additional characters. Here are some examples:
```
d{4} is the same as dddd.
dL{4}a is the same as dLLLLa.
udl{1}du is the same as udldu.
```
To define a custom character set from which the password generator randomly selects one character, you can use the [...] notation. The characters placed between the '[' and ']' brackets follow the same rules as the placeholders mentioned earlier. The '^' character is used to exclude the following placeholders from the character set. Here are some examples:

[dp] generates a single random character from the set of digits and punctuation.
[d\m@^\3]{5} generates five characters from the set "012456789m@" while excluding '3'.
[u_][u_] generates two characters from the set of uppercase letters and '_'.




## Logging examples:


```
11-05-23 21:05 randomPsw        INFO     Start randomPsw
11-05-23 21:05 randomPsw        INFO     Use template with key -t
11-05-23 21:05 randomPsw        DEBUG    Input -t: ddd
11-05-23 21:05 get_placeholder_t DEBUG    Count in loop from key -c (default 1): 7
11-05-23 21:05 brackets_set_func DEBUG    Result set in brackets: []
11-05-23 21:05 get_placeholder_t DEBUG    Template after loop: ['6', '8', '1']
11-05-23 21:05 brackets_set_func DEBUG    Result set in brackets: []
11-05-23 21:05 get_placeholder_t DEBUG    Template after loop: ['4', '0', '3']
11-05-23 21:05 brackets_set_func DEBUG    Result set in brackets: []
11-05-23 21:05 get_placeholder_t DEBUG    Template after loop: ['0', '8', '5']
11-05-23 21:05 brackets_set_func DEBUG    Result set in brackets: []
11-05-23 21:05 get_placeholder_t DEBUG    Template after loop: ['8', '5', '6']
11-05-23 21:05 brackets_set_func DEBUG    Result set in brackets: []
11-05-23 21:05 get_placeholder_t DEBUG    Template after loop: ['0', '4', '3']
11-05-23 21:05 brackets_set_func DEBUG    Result set in brackets: []
11-05-23 21:05 get_placeholder_t DEBUG    Template after loop: ['5', '3', '2']
11-05-23 21:05 brackets_set_func DEBUG    Result set in brackets: []
11-05-23 21:05 get_placeholder_t DEBUG    Template after loop: ['5', '3', '6']
11-05-23 21:06 randomPsw        INFO     Start randomPsw
11-05-23 21:06 randomPsw        INFO     Use template with key -t
11-05-23 21:06 randomPsw        DEBUG    Input -t: dd;d
11-05-23 21:06 get_placeholder_t DEBUG    Count in loop from key -c (default 1): 7
11-05-23 21:06 brackets_set_func DEBUG    Result set in brackets: []
11-05-23 21:06 get_placeholder_t ERROR    Character is not in placeholders and not escaped: ;
11-05-23 21:06 randomPsw        INFO     Start randomPsw
11-05-23 21:06 randomPsw        INFO     Use template with key -t
11-05-23 21:06 randomPsw        DEBUG    Input -t: dd;d
```


# Part 2


| Placeholder | Type  | Character Set |
|---|----|-----|
| a | Lower-Case Alphanumeric | abcdefghijklmnopqrstuvwxyz 0123456789 |
| A | Mixed-Case Alphanumeric | ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz 0123456789 |
| U | Upper-Case Alphanumeric | ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789 |
| h | Lower-Case Hex Character | 0123456789 abcdef | 
| H | Upper-Case Hex Character | 0123456789 ABCDEF |
| v | Lower-Case Vowel | aeiou |
| V | Mixed-Case Vowel | AEIOU aeiou |
| Z | Upper-Case Vowel | AEIOU |
| c | Lower-Case Consonant | bcdfghjklmnpqrstvwxyz |
| C | Mixed-Case Consonant | BCDFGHJKLMNPQRSTVWXYZ bcdfghjklmnpqrstvwxyz |
| z | Upper-Case Consonant | BCDFGHJKLMNPQRSTVWXYZ |
| b | Bracket ()[]{}<> |
| s | Printable 7-Bit Special Character | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ |
| S | Printable 7-Bit ASCII | A-Z, a-z, 0-9, !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ |
| x | Latin-1 Supplement Range |  [U+00A1, U+00FF] except U+00AD: ¡¢£¤¥¦§¨©ª«¬®¯ °±²³´µ¶·¸¹º»¼½¾¿ ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏ ÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß àáâãäåæçèéêëìíîï ðñòóôõö÷øùúûüýþÿ |
| \| | Char Set or Char Set | Позволяет случайно выбирать одно из двух множеств символов для генерации |