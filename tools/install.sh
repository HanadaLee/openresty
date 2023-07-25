#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

nginx_is_installed=$(command -v nginx | wc -l)
if [[ ${nginx_is_installed} == "1" ]];then
    echo "Nginx is installed"
    exit
fi

script_abs=$(readlink -f "$0")
script_dir=$(dirname ${script_abs})
nginx_dir=$(dirname ${script_dir})
if [ ${nginx_dir} != "/usr/local/openresty" ]; then
    mv -f /usr/local/openresty /usr/local/openresty-bak 2>/dev/null; true
    mv -f ${nginx_dir} /usr/local/
fi

user=www-data
group=www-data
egrep "^$group" /etc/group >& /dev/null
if [ $? -ne 0 ]
then
    groupadd $group
fi
egrep "^$user" /etc/passwd >& /dev/null
if [ $? -ne 0 ]
then
    useradd -g $group $user
fi

rm -f /usr/sbin/nginx.old
mv -f /usr/sbin/nginx /usr/sbin/nginx.old 2>/dev/null; true 
ln -sf /usr/local/openresty/sbin/nginx /usr/sbin/nginx
rm -rf /etc/nginx-bak
mv -f /etc/nginx /etc/nginx-bak 2>/dev/null; true 
ln -sf /usr/local/openresty /etc/nginx
rm -rf /var/log/nginx
ln -sf /usr/local/openresty/var/log /var/log/nginx 
rm -f /etc/systemd/system/nginx.service /lib/systemd/system/nginx.service
ln -sf /usr/local/openresty/systemd/nginx.service /etc/systemd/system/nginx.service
systemctl daemon-reload
systemctl enable nginx
systemctl start nginx
