import socket

import DNSPackageMaster as dnspm
import DNSCacheMaster as dnscm

SERVER = "8.8.8.8"


class UnprocessedPackage(Exception):
    pass


def process_RR(RR):
    print("New RR: " + str(RR))
    name, type, qclass, TTL, RDLENGTH, RDATA = RR
    if type == 1:
        cache.add_ipv4_address(name, RDATA, TTL)
    elif type == 12:
        name = name[:-13]  # remove ".in-addr.arpa"
        name = ".".join(reversed(name.split('.')))[1:]
        cache.add_name(name, RDATA, TTL)
    elif type == 28:
        cache.add_ipv6_address(name, RDATA, TTL)
    elif type == 2:
        cache.add_nsname(name, RDATA, TTL)
    else:
        print("not remembered")


def work_loop(cache):
    global sock

    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", 53))

        data, addr = sock.recvfrom(2048)

        print("##########################################################")
        print("NEW QUERY!!!")
        try:
            package = dnspm.parse_package(data)

            print("----------------------------------------------------------")
            print("(QNAME, QTYPE, QCLASS)")
            print("package.questions: " + str(package.questions))
            for name, type, qclass in package.questions:
                if qclass == 1:
                    if type == 1:
                        answers = cache.try_find_ipv4_address(name)
                    elif type == 12:
                        ip = name[:-13]  # remove ".in-addr.arpa"
                        ip = ".".join(reversed(ip.split('.')))[1:]
                        answers = cache.try_find_name(ip)
                    elif type == 28:
                        answers = cache.try_find_ipv6_address(name)
                    elif type == 2:
                        answers = cache.try_find_nsname(name)
                    else:
                        raise UnprocessedPackage(f"unprocessed type {type}")

                    if answers:
                        print("!!!Answers found in cache!!!")
                        for answer, TTL in answers:
                            package.add_answer(name, type, qclass, TTL, answer)
                        print("(NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA)")
                        print("package.answers: " + str(package.answers))
                    else:
                        print("###There was no answer in the cache###")
                        sock.sendto(package.get_data(), (SERVER, 53))
                        data, _ = sock.recvfrom(2048)

                        package = dnspm.parse_package(data)
                        print("(NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA)")
                        for RR in package.answers + package.authoritys + package.additionals:
                            process_RR(RR)
                else:
                    raise UnprocessedPackage(f"unprocessed class {qclass}")

            sock.sendto(package.get_data(), addr)
        except UnprocessedPackage as e:
            sock.sendto(data, (SERVER, 53))
            data, _ = sock.recvfrom(2048)
            sock.sendto(data, addr)
            print(f"@@@Unprocessed Package@@@\nERROR: {e}")

        print("----------------------------------------------------------")
        sock.close()

        dnscm.save_cache(cache)


if __name__ == "__main__":
    print('The server starts working')

    global cache
    cache = dnscm.load_cache()

    work_loop(cache)
