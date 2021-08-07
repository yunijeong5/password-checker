import requests # pip install requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again.')
    # returned data (res) has remaining hash string (w/o first 5 char; aka tailed hashes)
    # and the number that they have been hacked.
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines()) # list comprehension
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwnd_api_check(password):
    # Check pwd if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)

    return get_password_leaks_count(response, tail)


# ver1. Reads passwords from command line argv
# def main(args):
#     for password in args:
#         count = pwnd_api_check(password)
#         if count:
#             print(f'{password} was found {count} times.')
#         else:
#             print(f'{password} was not found!')
#     return 'done!'


# ver2. Reads passwords from a .txt file
def main(filename):
    try:
        with open(filename) as file:
            password_list = file.read().split()
            for password in password_list:
                count = pwnd_api_check(password)
                if count:
                    print(f'{password} was found {count} times.')
                else:
                    print(f'{password} was not found!')
            return 'done!'
    except FileNotFoundError as err:
        print(f'Check your file name: {err}')


if __name__ == '__main__':
    # ver1. Reads passwords from command line argv
    # sys.exit(main(sys.argv[1]))

    # ver2. Reads passwords from a .txt file
    sys.exit(main(sys.argv[1]))

