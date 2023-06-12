#!/usr/bin/env python

import re
import random
import string
import secrets
import logging
import argparse

DIGITS = string.digits
LETTERS = string.ascii_letters
SPECIAL_CHARS = string.punctuation

DEFAULT_ALPHABET = LETTERS + DIGITS

# Range [U+00A1, U+00FF] except U+00AD
LATIN1_SUPPLEMENT = ''.join({chr(i) for i in range(ord('\u00A1'), ord('\u00FF') + 1) if i != ord('\u00AD')})

VALID_UNICODE = [
    ({"min": "0001", "max": "d7ff"}, "n"),  # 0001-d7ff - allowed range ("n" - no filtering)

    ({"min": "ffff", "max": "ffff"}, "n"),  # e000-d7ff - allowed range ("n")

    ({"min": "0009", "max": "0009"}, "y"),  # \t - filtered symbol ("y" - apply filtering)

    ({"min": "000A", "max": "000A"}, "y"),  # \n - filtered symbol ("y")

    ({"min": "000D", "max": "00D"}, "y"),  # \r - filtered symbol ("y")

    ({"min": "FFFF", "max": "FFFF"}, "y")  # FFFF - filtered symbol ("y")
]

PLACEHOLDERS = {
    'd': DIGITS,
    'l': 'abcdefghijklmnopqrstuvwxyz',
    'L': LETTERS,
    'u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'p': ',.;:',
    'a': 'abcdefghijklmnopqrstuvwxyz0123456789',
    'A': 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    'U': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    'h': '0123456789abcdef',
    'H': '0123456789ABCDEF',
    'v': 'aeiou',
    'V': 'AEIOUaeiou',
    'Z': 'AEIOU',
    'c': 'bcdfghjklmnpqrstvwxyz',
    'C': 'BCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz',
    'z': 'BCDFGHJKLMNPQRSTVWXYZ',
    'b': '()[]{}<>',
    's': "!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~",
    'S': DEFAULT_ALPHABET + SPECIAL_CHARS,
    'x': LATIN1_SUPPLEMENT
}

AVAILABLE_CHAR_TEMPLATE = ['\\', '{', '}', '[', ']']


class PatternError(Exception):

    def __init__(self, *args):
        if args:
            self.message = args[0]
        else:
            self.message = None

    def __str__(self):
        if self.message:
            return 'Invalid syntax, {0} '.format(self.message)
        else:
            return 'PatternError'



def main():
    """
    Main function for password generation.
    :return: argument: Parsed command-line arguments.
    """

    parser = argparse.ArgumentParser(prog='PswGen', description='Generate a random password')
    #  Set length of password and generate random password from set {small lateral ASCII, big lateral ASCII, digit}
    parser.add_argument('-n', dest='pwd_length', metavar='N', type=int, default=8,
                        help='Length of the password (default: 8)')
    # Set number of passwords
    parser.add_argument('-c', dest='count', metavar='N', type=int, default=1,
                        help='Numbers of password')
    # Set character set
    parser.add_argument('-S', dest='charset', metavar='String', type=str, default=DEFAULT_ALPHABET,
                        help='The character set can be defined directly in the argument line.')
    # Verbose mode
    parser.add_argument('-v', action='count', default=0, help='Verbose mode (-v |-vv |-vvv )')

    # Getting list of patterns from file and generate for each random password
    parser.add_argument('-f', dest='file', metavar='PATH',
                        help='Read patterns from file (one line - one pattern')
    # Randomly permute characters of password
    parser.add_argument('-p', dest='random_permute', action='store_true',
                        help='Randomly permute characters of password')
    # Set template for generate passwords
    parser.add_argument('-t', dest='template', metavar='template', type=str,
                        help='Set template for generate passwords')

    argument = parser.parse_args()

    # Check the logging level with the given key -v
    if not vars(argument):
        parser.print_usage()
    else:
        if argument.v == 0 or not argument.v:
            logging.getLogger('').setLevel(logging.ERROR)
        if argument.v == 1:
            logging.getLogger('').setLevel(logging.WARNING)
        if argument.v == 2:
            logging.getLogger('').setLevel(logging.INFO)
        if argument.v == 3:
            logging.getLogger('').setLevel(logging.DEBUG)
    return argument


def get_valid_unicode_string(str_for_filtering: str) -> str:
    """
    This code filters the string str_for_filtering by checking for the presence of valid characters.
    It iterates through each character of the string and checks if it belongs to
    the valid character ranges specified in the VALID_UNICODE variable.
    If a character is deemed valid, it is added to the resulting string filtered_str.
    :param str_for_filtering: The input string to be filtered.
    :return: The filtered string containing only characters allowed by the VALID_UNICODE ranges.
    """

    filtered_str = ""
    if str_for_filtering and isinstance(str_for_filtering, str):
        character_ranges = sorted(VALID_UNICODE, key=lambda item: item[1], reverse=True)
        for char in str_for_filtering:
            char_codepoint = ord(char)
            is_valid_char = False
            for char_range, allow_filtering in character_ranges:
                range_min = hex_str_unicode_to_int_unicode(char_range["min"])
                range_max = hex_str_unicode_to_int_unicode(char_range["max"])
                if char_codepoint == range_min and char_codepoint == range_max and allow_filtering == "y":
                    # Character is an exact match and should be filtered
                    is_valid_char = False
                    break
                elif range_min <= char_codepoint <= range_max and allow_filtering == "n":
                    # Character falls within the range and should not be filtered
                    is_valid_char = True
                    break
            if is_valid_char:
                filtered_str += char
        return filtered_str


def hex_str_unicode_to_int_unicode(hex_str_unicode: str) -> int:
    """
    Converts a hex string representation of Unicode to its corresponding integer Unicode value.
    :param hex_str_unicode: The hex string representation of Unicode.
    :return: The integer Unicode value.
    """

    char_unicode = chr(int(hex(int(hex_str_unicode, 16)), 16))
    int_unicode = ord(char_unicode)
    return int_unicode


def password_generator(pwd_length: int, count: int, alphabet: str) -> list[str]:
    """
    Generate random passwords.
    :param alphabet: The set of characters to choose from when generating passwords
    :param count: The number of passwords to generate.
    :param pwd_length: The length of each password.
    :return: A list of randomly generated passwords.
    """

    logger_func = logging.getLogger('Password_generator')
    logger_func.info('Start Password_generator')
    passwords = []
    for _ in range(count):
        password = ''
        for length in range(pwd_length):
            password += ''.join(secrets.choice(alphabet))
        logger_func.info('Generated password: %s', password)
        passwords.append(password)
    return passwords


def unique_char_set(char_list: list) -> str:
    """
    Remove repeated characters from a list and return a string with only the unique characters.
    :param char_list: The list of characters.
    :return: A string containing only the unique characters from the input list.
    """

    unique_chars = []
    for ch in char_list:
        if ch not in unique_chars:
            unique_chars.append(ch)
    unique_set = "".join(unique_chars)
    return unique_set


def check_brackets(template: str) -> bool:
    """
    Check if the brackets in the given string template are balanced.
    :param template: The string template to check.
    :return: bool: True if the brackets are balanced, False otherwise.
    """

    stack = []
    for char in template:
        if char == '[':
            stack.append(char)
        elif char == ']':
            if len(stack) == 0 or stack[-1] != '[':
                return False
            stack.pop()
    if len(stack) != 0:
        return False
    return True


def randomPsw(key):
    """
    Generate passwords based on the provided key and options.
    :param key: The key object containing information about the password generation options from function main.
    :return: None
    """

    logger_func = logging.getLogger('randomPsw')
    logger_func.info('Start randomPsw')
    logger_func.warning('Count in func from key -c (default 1): %s', key.count)
    logger_func.warning('Length in func from key -n (default 8): %s', key.pwd_length)

    # Key -c -n, simple pass gen
    if DEFAULT_ALPHABET == key.charset and not key.template and not key.file:
        logger_func.info('Use default dictionaries: digits upperCase lowCase ')
        output_password(password_generator(key.pwd_length, key.count, DEFAULT_ALPHABET))

    # Key -S
    elif DEFAULT_ALPHABET != key.charset and not key.template:
        logger_func.info('Use template with key -S ')
        logger_func.debug('Input -S: %s ', key.charset)
        char_set_s = get_valid_unicode_string(key.charset)
        char_set_s = define_charset(char_set_s)
        output_password(password_generator(key.pwd_length, key.count, char_set_s))

    elif key.template and not key.file:
        try:
            template = get_valid_unicode_string(key.template)
            logger_func.info('Use template with key -t')
            logger_func.debug('Input -t: %s', template)
            if key.charset == DEFAULT_ALPHABET and key.pwd_length == 8:
                output_password(get_placeholder(template))
            else:
                raise ValueError("Option -t cannot be used with -n or -S")
        except Exception as e:
            logger_func.error(str(e))

    # Key -f. Read file
    elif key.file:
        try:
            logger_func.info('Read patterns from file')
            logger_func.debug('Name file: %s', key.file)
            with open(key.file, "r") as file:
                for line in file:
                    if line.strip() == '':
                        logger_func.error('Empty line')
                        continue
                    template = line.strip()
                    try:
                        template = get_valid_unicode_string(template)
                        output_password(get_placeholder(template))
                    except Exception as e:
                        logger_func.error(str(e))
        except FileNotFoundError as e:
            logger_func.error("File not found: %s", key.file)


def output_password(password_list: list) -> None:
    """
    Prints each password in the provided list.
    :param password_list: The list of passwords to be printed.
    :return: None
    """

    if password_list is not None:
        for password in password_list:
            print(password)


def brackets_set_func(brackets: list) -> list:
    """
    Generate random results based on the placeholders and options within the brackets.
    :param brackets: A list of brackets containing placeholders and options.
    :return: A list of random results generated based on the brackets.
    :raise ValueError: If there is invalid syntax or configuration within the brackets.
    """

    logger_func = logging.getLogger('brackets_set_func')
    placeholder_list = []
    placeholder_or = []
    result_brackets = []
    for bracket in brackets:
        sub_list = []
        remove_list = []

        # Find number of multiplicator in {}
        mult = re.findall(r'\{(\d)\}', bracket)
        mult = int(mult[0]) if mult and mult[0] is not None else 1
        logger_func.debug("Create multiplication for brackets: %s", mult)
        if bracket[1] == '|':
            raise PatternError("placeholder '|' cannot be at the beginning or at the end of brackets")
        if mult > 1:
            if bracket[-5] == '|' and bracket[-6] != '\\':
                raise PatternError("placeholder '|' cannot be at the beginning or at the end of brackets")

        # Check placeholder in brackets
        for ch in range(len(bracket)):
            if bracket[ch] in PLACEHOLDERS and bracket[ch - 1] != '\\':
                plc_hld = PLACEHOLDERS[bracket[ch]]
                sub_list.append(plc_hld)
            elif bracket[ch - 1] == '\\':
                sub_list.append(bracket[ch])
            elif bracket[ch] == '^':
                if bracket[ch + 1] == '\\':
                    sub_list.append(bracket[ch])
                else:
                    raise PatternError("in [^]. Symbol after '^' should be escaped")
            elif bracket[ch] in DIGITS and bracket[ch - 1] == '{':
                continue
            elif bracket[ch] == '}' and bracket[ch - 2] == '{':
                continue

            # Looking for where we have a placeholder | and add it to a separate set
            elif bracket[ch] == '|' and bracket[ch - 1] != '\\':
                if bracket[ch - 1] in PLACEHOLDERS and bracket[ch + 1] in PLACEHOLDERS:
                    remove_list.append(PLACEHOLDERS[bracket[ch - 1]])
                    remove_list.append(PLACEHOLDERS[bracket[ch + 1]])
                else:
                    raise PatternError("between | not a placeholder")
            else:
                if bracket[ch] not in AVAILABLE_CHAR_TEMPLATE:
                    raise PatternError
        sub_list.append(mult)
        remove_list = list(set(remove_list))    # Remove duplicates
        placeholder_or.append(remove_list)   # Create list for placeholder or
        placeholder_list.append(sub_list)   # Create list where last element is multiplication
    logger_func.info('Set placeholders in brackets: %s', placeholder_list)
    logger_func.info('Set placeholder "|" in brackets: %s', placeholder_or)

    # Randomly from the set we choose one of our two "or"
    for sublist in range(len(placeholder_list)):
        result_list = []
        remove_symbol = []
        for _ in range(placeholder_list[sublist][-1]):
            copy_placeholder_list = [sublist.copy() for sublist in placeholder_list]
            remove_random = [random.sample(sub_list, len(sub_list) - 1)
                             if len(sub_list) != 0 else None for sub_list in placeholder_or]

            if remove_random[sublist] is not None:
                logger_func.debug('Set remove_random "|" in brackets: %s', remove_random)
                for sublist_remove in remove_random[sublist]:
                    copy_placeholder_list[sublist].remove(sublist_remove)
                logger_func.debug('Set placeholder in brackets after remove_random: %s', copy_placeholder_list)
            result1 = ''
            alphabet = ''
            for _ in range(len(copy_placeholder_list[sublist]) - 1):
                alphabet = ''.join(copy_placeholder_list[sublist][:-1])
                caret_symbol = re.findall(r'\^(.)', alphabet)
                alphabet = re.sub(r'\^(.)', '', alphabet)
                remove_symbol = caret_symbol if caret_symbol and caret_symbol[0] is not None else []

                # Remove caret symbol from list
                for symbol in remove_symbol:
                    alphabet = alphabet.replace(symbol, '')
                alphabet = unique_char_set(alphabet)
                result1 = random.choice(alphabet)
            result_list.append(result1)
            logger_func.debug('Alphabet: %s', alphabet)
        logger_func.warning('Removed symbol: %s', remove_symbol)
        logger_func.debug('Result after loop: %s', result_list)
        result_list = ''.join(result_list)
        result_brackets.append(result_list)
        logger_func.info('Result set in brackets: %s', result_brackets)
    return result_brackets


def define_charset(charset: str) -> str:
    """
    Define the alphabet for password generation based on the provided charset.
    :param charset: The charset containing placeholders and characters.
    :return: The alphabet for password generation.
    """

    logger_func = logging.getLogger('define_charset')
    alphabet = set()

    # Create alphabet for key -S and delete all \
    for placeholders in PLACEHOLDERS.keys():
        while '\\' + placeholders in charset:
            charset = charset.replace('\\' + placeholders, '')
            alphabet = alphabet.union(PLACEHOLDERS[placeholders])
    alphabet = alphabet.union(set(charset))
    alphabet = ''.join(alphabet)
    logger_func.debug('Alphabet in S: %s', alphabet)
    return alphabet


def get_placeholder(template: str) -> list[str]:
    """
    Generate passwords based on the provided template.
    :param template: The template string specifying the password structure.
    :return: A list of generated passwords.
    """

    logger_func = logging.getLogger('get_placeholder')
    result_templates = []

    # Find all charters in symbol
    find_brackets = re.findall(r'\[[^\]]+\](?:\{[^\}]+\})?', template)

    # Delete all charter inside brackets
    template = re.sub(r'\[(.*?)\]', '[]', template)
    logger_func.warning('Count in loop from key -c (default 1): %s', args.count)

    # Key -t can be used with key -c (count)
    for _ in range(args.count):
        template_output = []

        # Create charset in brackets
        brackets = brackets_set_func(find_brackets)
        for placeholder in range(len(template)):

            # Check brackets in template
            if '[' in template:
                if template[placeholder] == '[':
                    if template[placeholder - 1] == '\\':
                        template_output.append(template[placeholder])
                    else:
                        template_output.append(template[placeholder])
                        if not check_brackets(template):
                            raise PatternError('bracket not closed: %s ' % template[placeholder])
                elif template[placeholder] == ']':
                    if template[placeholder - 1] == '\\':
                        template_output.append(template[placeholder])
                    else:
                        template_output.append(template[placeholder])
                        if not check_brackets(template):
                            raise PatternError('bracket not closed: %s' % template[placeholder])
            if template[placeholder - 1] == '\\':
                if template[-1] != '\\':
                    template_output.append(template[placeholder])
                else:
                    raise PatternError('bracket not closed: %s' % template[placeholder])
            elif template[placeholder] == '{' and template[placeholder + 2] == '}' \
                    and template[placeholder - 2] != '\\':
                if template[placeholder - 1] != ']':
                    for x in range(int(template[placeholder + 1]) - 1):
                        if template[placeholder - 1] in PLACEHOLDERS:
                            template_output.append(random.choice(PLACEHOLDERS[template[placeholder - 1]]))
                        else:
                            raise PatternError("Character is not placeholders: %s" % template[placeholder - 1])
            elif template[placeholder] in DIGITS and template[placeholder - 1] == '{':
                continue
            elif template[placeholder] == '}' and template[placeholder - 2] == '{':
                continue
            elif template[placeholder] in PLACEHOLDERS:
                if template[placeholder] != '\\':
                    template_output.append(random.choice(PLACEHOLDERS[template[placeholder]]))
            elif template[placeholder] not in PLACEHOLDERS and template[placeholder] != '\\' \
                    and template[placeholder] not in AVAILABLE_CHAR_TEMPLATE:
                raise PatternError("Character is not in placeholders and not escaped: %s" % template[placeholder])
        logger_func.debug('Template after loop: %s', template_output)
        template_output = ''.join(template_output)

        # Fill the brackets from the function brackets_set_func
        for bracket in brackets:
            template_output = template_output.replace('[]', bracket, 1)

        # Key -p, random permute
        if args.random_permute:
            permute_list = list(template_output)
            random.shuffle(permute_list)
            shuffled_list = ''.join(permute_list)
            logger_func.warning('Template after shuffling: %s', shuffled_list)
            result_templates.append(shuffled_list)
        else:
            result_templates.append(template_output)
    logger_func.info("Output results to CLI: %s", result_templates)
    return result_templates


if __name__ == '__main__':

    # Configure logging. The handler specifies the file and format.
    logging.basicConfig(level=logging.CRITICAL,
                        format='%(asctime)s %(name)-16s %(levelname)-8s %(message)s',
                        datefmt='%d-%m-%y %H:%M',
                        handlers=[logging.FileHandler(filename='password_generator.log', mode='w', encoding='utf-8')]
                        )

    console = logging.StreamHandler()
    console.setLevel(logging.ERROR)
    formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')

    # Use the format
    console.setFormatter(formatter)

    # Add the console handler to the root logger
    logging.getLogger('').addHandler(console)
    logging.info('Starting pswgen app')

    args = main()
    randomPsw(args)
