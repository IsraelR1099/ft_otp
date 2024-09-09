# Cybersecurity piscine

# ft_otp

## How does it work?

Lets assume we are currently in Beijing (China) and the local time is 4 December 2018, 20:24:20 (UTC+8). The date and time at that moment at 0 longitude meridian.

Convert this date time (4 December 2018, 12:24:20) to Unix Epoch Time (Tunix). Unix Epoch Time is the number of seconds that have elapsed since, 1 January 1970 00:00:00 UTC, not counting leap seconds.

If the date and time at 0 longitude is 4 December 2018, 12:24:20 then Tunix = 1543926260 seconds.

Equation:

```mathematica
N = floor(Tunix / ts)

N = function which rounds a number downward to its nearest integer.
Tunix = Number of seconds that have elapsed since, 1 January 1970 00:00:00 UTC
ts = time step, by default the time step is 30 sec.

N = floor(1543926260 / 30)
N = 51464208
```

Convert the number of time steps (N) into a hexadecimal value. The hexadecimal value must have 16 hexadecimal characters (=8 bytes). If not, prepend with 0’s.

```mathematica
Ndec = 51464208
Nhex = 0x0000000003114810
```

Convert the hexadecimal value (Nhex = 0x0000000003114810) into 8 bytes array and assign it to variable m (=message).

Convert the shared secret key into a 20 bytes array and assign it to variable K.

Calculate the HMAC hash using the HMAC-SHA 1 algorithm.

This HMAC hash size is 160 bits (=20 bytes).

```mathematica
HMAC hash = AF 16 86 8F  E5 DB 00 C1 58 75 76 A7 F8 99 F5 28 AB 80 5E 9A
```

Get the last 4 bits of this hash value and get its integer value. In this example, the last 4 bits is 0xA which represents integer 10. This integer is called the offset.

Starting from the offset, get the first 4 bytes from the HMAC hash.

![Screenshot from 2024-09-09 11-34-14.png](Cybersecurity%20piscine%20c6151e42dddf4bc7a1622c149b9d873b/Screenshot_from_2024-09-09_11-34-14.png)

Apply a binary operation for each byte.

![Screenshot from 2024-09-09 11-35-43.png](Cybersecurity%20piscine%20c6151e42dddf4bc7a1622c149b9d873b/Screenshot_from_2024-09-09_11-35-43.png)

We get the new binary value = 0x76A7F899.

Conver this new binary value to integer = 1990719641.

Calculate the token:

```mathematica
1990719641 % 10^n.

Where n is the token size. In this example is 6.

Token = 1990719641 % 10^6 = 719641
```

If the token size is < 6 then we prefix with 0’s.

Every 30 seconds a new token is generated.

### Sources

https://www.youtube.com/watch?v=VOYxF12K1vE

https://www.freecodecamp.org/news/how-time-based-one-time-passwords-work-and-why-you-should-use-them-in-your-app-fdd2b9ed43c3/