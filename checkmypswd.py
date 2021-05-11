import requests
import hashlib
import sys

"""Loops through given file and checks the passwords in it"""


def request_api_data(query_char):
    """
    In order to protect the value of the source password being searched for,
    Pwned Passwords also implements a k-Anonymity model that allows a password to be searched for by partial hash.
    This allows the first 5 characters of a SHA-1 password hash (not case-sensitive) to be passed to the API:
    GET https://api.pwnedpasswords.com/range/{first 5 hash chars}
    When a password hash with the same first 5 characters is found in the Pwned Passwords repository,
    the API will respond with an HTTP 200 and include the suffix of every hash beginning with the specified prefix,
    followed by a count of how many times it appears in the data set.
    """
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leak_count(hashes, hash_to_check):
    """
    Splits the API response from pwnedpasswords.com
    and checks how many time it has been hacked
    :param hashes: API response without first 5 chars
    :param hash_to_check: our hashed password without first 5 chars
    :return:
    """
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    """
    Hashes and splits our password in first 5 chars and the rest
    """
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leak_count(response, tail)


def main(file):
    with open(file, 'r', encoding='utf-8') as f:
        for password in f:
            count = pwned_api_check(password.strip())
            if count:
                print(f'{password} was found {count} times... change your password!')
            else:
                print(f'{password} was not found. You\'re good!')


if __name__ == '__main__':
    try:
        main(sys.argv[1])
    except IndexError:
        print('Specify the file with passwords, please')
