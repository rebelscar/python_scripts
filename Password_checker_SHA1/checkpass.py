from requests import Response, get
from hashlib import sha1
from sys import argv as sysArgs

# Usage: >> python3 checkpass.py password1 password2 password3


def request_api_data(query_first_five):
    url = 'https://api.pwnedpasswords.com/range/' + query_first_five
    response = get(url)
    if response.status_code != 200:  # if you get 400 or something else, check the url
        raise RuntimeError(
            f'Error fetching: {response.status_code}, check the api and try again!')
    return response


def password_leaks(all_hashes, your_hash):
    all_hashes = (line.split(':') for line in all_hashes.text.splitlines())
    for h, count in all_hashes:
        if h == your_hash:
            return count
    return 0


def pwned_chech(password):
    sha1_password = sha1(password.encode('utf-8')).hexdigest().upper()
    # grab first 5 characters of the hash and the rest
    first5, rest = sha1_password[:5], sha1_password[5:]
    response = request_api_data(first5)
    return password_leaks(response, rest)


def main(args):
    for password in args:
        count = pwned_chech(password)
        if(count):
            print(f'{password} was found {count} times.')
        else:
            print(f'{password} was not found.')
    print('Done!')


if __name__ == '__main__':
    main(sysArgs[1:])

# In comparison to the normal search on the website,
# this way you won't send them your whole password,
# but just a part of its SHA1 hash and from the retrieved list of hashes
# it'll check the one you're searching for
