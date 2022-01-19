## Introducción
Este script fue diseñado para extraer visualizaciones ya creadas en Kibana y plasmarlas en un correo electronico con formato HTML. Las visualizaciones soportadas hasta ahora son:

- Tablas (Data Table, only configured with `Split Rows` and `Terms` as aggregations)
- Graficos de torta (Pie, only configured with `Split Slices` and `Terms` as aggregations)
- Graficos de barra o histogramas (Vertical Bar, only configured with `Split Series` and `Terms` as aggregations)

## Cómo utilizarlo?
### Instalar dependencias
Para generar los graficos y trabajar con la informacion extraida de Elasticsearch y Kibana, es necesario instalar algunos modulos en el framework the Wazuh para poder utilizarlo:
```
/var/ossec/framework/python/bin/pip3 install email
/var/ossec/framework/python/bin/pip3 install pandas
/var/ossec/framework/python/bin/pip3 install matplotlib
```
### Generar la lista de visualizaciones
El script va a consultar una CDB List, que usted puede generar tanto desde la UI de Wazuh como desde la consola, en la cual se deberán especificar los IDs de las visualizaciones que se pretende que aparezcan en el correo de reporte, un ejemplo:
```
eebeaf20-1d86-11ec-8551-f505aa070eaf:180
c83ac5e0-165c-11ec-9126-8957fb49eea0:180
0556cfc0-09c7-11ec-b7d0-ad7375fceb8d:90
```
Se puede ver de un lado los IDs correspondientes, y del otro los numeros que corresponden a la cantidad de dias que se van a tener en cuenta como tiempo para la consulta de la informacion en Elasticsearch.
Se le debe colocar un nombre a la lista que luego se especificará en el comando del script.

Para extraer dichos IDs, se debe verificar la visualizacion creada, por ejemplo:
![image](https://user-images.githubusercontent.com/37050249/149815309-893b4249-f16e-4b38-be62-10f2157d516a.png)

### Otorgar permisos
Otorgar permisos de ejecucion y ajustar el ownership:
```
chmod ug+x /var/ossec/integrations/custom-elastic-reports
chown root:ossec /var/ossec/integrations/custom-elastic-reports
```
Notese, que no se esta usando la extension `.py`, no es por nada especial, se puede conservar la extension sin problemas.

### Ejecutar el Script
El script se puede ejecutar de manera manual, o mediante un wodle command, los parametros son los siguientes:
```
# python custom-elastic-reports -h
usage: custom-elastic-reports.py [-h] --creds CREDS [CREDS ...] --elk-server ELK_SERVER [ELK_SERVER ...] [--kbn-server KBN_SERVER [KBN_SERVER ...]] --smtp SMTP [SMTP ...] --sender SENDER
                                 [SENDER ...] --to TO [TO ...] --cdblist CDBLIST [CDBLIST ...]

Create email Reports from custom visualizations in Kibana

options:
  -h, --help            show this help message and exit
  --creds CREDS [CREDS ...]
                        Elasticsearch credentials (user:password)
  --elk-server ELK_SERVER [ELK_SERVER ...]
                        Elasticsearch server address
  --kbn-server KBN_SERVER [KBN_SERVER ...]
                        Kibana server address
  --smtp SMTP [SMTP ...]
                        SMTP Server address
  --sender SENDER [SENDER ...]
                        Sender email address
  --to TO [TO ...]      Recipient email address
  --cdblist CDBLIST [CDBLIST ...]
                        Name of the CDBList used to get the visualizations
```
Como un ejemplo:
```
/var/ossec/integrations/custom-elastic-reports --to destino@wazuh.com --elk-server 10.10.10.220 --smtp 10.10.10.90 --sender origen@wazuh.com --creds admin:admin --cdblist report-list
```
No es necesario especificar el servidor de Kibana, si no se especifica, toma como servidor de Kibana el mismo Elasticsearch server.

Si se ejecuta manualmente, este devuelve el log en pantalla, mientras que si se ejecuta mediante wodle command, se escribe el log en el archivo integrations.log.

### Mediante wodle command
Para ejecutarlo mediante este metodo, es necesario modificar el archivo de configuraciones ossec.conf the uno de las Managers del cluster (preferentemente el Master) e incluir la siguiente configuracion:
```
  <wodle name="command">
    <disabled>no</disabled>
    <tag>elastic-reports</tag>
    <command>/var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-elastic-reports --to destino@wazuh.com --elk-server 10.10.10.220 --smtp 10.10.10.90 --sender origen@wazuh.com --creds admin:admin --cdblist report-list</command>
    <interval>1w</interval>
    <ignore_output>yes</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>300</timeout>
  </wodle>
```
En este caso, se le da un tiempo de ejecucion de no mas de cinco minutos (timeout=300) y un intervalo de ejecucion de 1 semana, es decir que este reporte va a ser semanal.
