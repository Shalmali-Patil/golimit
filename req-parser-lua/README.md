Build a docker using below command - 
docker build -t="openresty1" .

Run it locally using 
docker run --name openresty1 -d -p 8091:80 openresty1

Modify /etc/nginx/conf.d/default.conf from this docker to update interceptor code
Once the nginx config is modified, one should restart the nginx service to activate new configurations. To do that, use below command
/usr/local/openresty/nginx/sbin/nginx -s reload

Use postman to fire http POST call to auction endpoint from server side wrapper - http://localhost:8091/openrtb/2.4/ 
The POST data should be the oRTB request JSON.

Once fired, as per nginx location config for auction endpoint, it will extract site.publisher.id from oRTB request and add it in the header as x-my-header



