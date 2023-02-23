# Summary



## about target

tip:  10.129.131.171

hostname: Silo

Difficulty: Medium



## about attack

+ oracle tns attack, sid enum and brute force, login and write shell.
+ Odat install, oracle basic doesn't support arm, nmap brute force failed. 
+ 暂时放着
+ 





**attack note**







# Enumeration

## nmap scan

light scan

```bash
nmap -p- --min-rate=1000 -T4 -oN nmap.light $tip


```



Heavy scan

```bash
export port=$(cat nmap.light | grep ^[0-9] | cut -d "/" -f 1 | tr "\n" "," | sed s/,$//)
sudo nmap -A -O -p$port -sC -sV -T4 -oN nmap.heavy $tip


```





## oracle enum



![image-20221002123015649](./images/image-20221002123015649.png)



sid

![image-20221002123304850](./images/image-20221002123304850.png)



Brute force, failed.

wordlist, both failed,  seperated with / and space

![image-20221002132119311](./images/image-20221002132119311.png)



![image-20221002132028430](./images/image-20221002132028430.png)



![image-20221002132043574](./images/image-20221002132043574.png)



# Exploitation





# Privesc



## Post Enumeration





## System





## proof

```bash


```



