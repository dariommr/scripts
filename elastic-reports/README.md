## Update
03/02/2022 - Added the function to extract the visualizations from a dashboard.

## Documentation

<details open>
<summary>English Documentation</summary>
<br>
  
  ## Rationale

  This script was intended to be used for extracting visualizations already created in Kibana and writting them into an HTML format email message. The supported visualizations are: 

  - Tables (Data Table, only configured with `Split Rows` and `Terms` as aggregations)
  - Pie Charts (Pie, only configured with `Split Slices` and `Terms` as aggregations)
  - Bar Charts or Histograms (Vertical Bar, only configured with `X-axis` and `Terms` as aggregations)

  ## How to use it?
  ### Install the dependencies
  In order to generate charts and work with the information extracted from Kibana and Elasticsearch, it is needed to install some python modules in the Wazuh framework:
  ```
  /var/ossec/framework/python/bin/pip3 install email
  /var/ossec/framework/python/bin/pip3 install pandas
  /var/ossec/framework/python/bin/pip3 install matplotlib
  ```
  ### Using a visualization list
  >Only while using the `--cdblist` parameter
  
  The script will query a CDB List that can be generated from the Wazuh UI (Kibana App) or through the terminal console of the Wazuh Manager, in which you need to specify the visualizations ID that you want to add to the report thet will be sent in the email message, for instance:
  ```
  eebeaf20-1d86-11ec-8551-f505aa070eaf:180
  c83ac5e0-165c-11ec-9126-8957fb49eea0:180
  0556cfc0-09c7-11ec-b7d0-ad7375fceb8d:90
  ```
  From one side you can see the IDs regarding the visualizations, on the other side, you can see the number of days that will be used to build the timeframe of the query for Elasticsearch. You will have to use the `--time` parameter regardless of the time you applied for every visualization, but the time in the CDB list will have precedence over the `--time` parameter. If for any reason the script can not read the time from the list, it will apply the time from the parameter.
  The list must have a name specified that later will be added as a parameter in the script execution.

  To extract those IDs, you need to verify the URL of the created visualization, for instance:
  ![image](https://user-images.githubusercontent.com/37050249/149815309-893b4249-f16e-4b38-be62-10f2157d516a.png)

  ### Give permissions to the script
  Add execution permissions to the script and change the ownership:
  ```
  chmod ug+x /var/ossec/integrations/custom-elastic-reports.py
  chown root:ossec /var/ossec/integrations/custom-elastic-reports.py
  ```
  
  ### Using a dashboard
  You can create a dashboard (having in mind the limits of the script described in the Rationale section) that contain all the visualizations. Take note the name of the dashboard you are creating because that will be the parameter you have to add to the script command.

  ### Execute the script
  It can be executed manually, or through a wodle command, the parameters are as follows:
  ```
  $ python custom-elastic-reports.py --help
  usage: custom-elastic-reports.py [-h] --creds CREDS [CREDS ...] --elk-server ELK_SERVER [ELK_SERVER ...] [--kbn-server KBN_SERVER [KBN_SERVER ...]] --smtp SMTP [SMTP ...] --sender SENDER
                                 [SENDER ...] --to TO [TO ...] [--dashboard DASHBOARD | --cdblist CDBLIST] --time TIME [TIME ...]

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
  --dashboard DASHBOARD
                        Name of the dashboard containing the visualizations. Can not use --cdblist with this option
  --cdblist CDBLIST     Name of the cdb list containing the visualizations. Can not use --dashboard with this option
  --time TIME [TIME ...]
                        Filter the visualizations for last N days
  ```
  An example:
  ```
  python custom-elastic-reports.py --creds admin:admin --elk-server 10.10.10.220 --smtp 10.10.10.90 --sender dariomenten@gmail.com --to test.alerts.dmr@gmail.com  --dashboard "Basic Dashboard" --time 180 days
  ```
  It is not needed to specify the Kibana server, if it is not specified it assumes the Elasticsearch server contains the Kibana service too.

  If it is executed manually, it output the log to the std-out, otherwise (through a wodle command), you will find the logs in the logfile.

  ### With a wodle command
  To execute it through this method, it is necessary to modify the ossec.conf configuration file of one Wazuh Manager node of the cluster (Suggested the master) and include the following setting:
  ```
    <wodle name="command">
      <disabled>no</disabled>
      <tag>elastic-reports</tag>
      <command>/var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-elastic-reports.py --creds admin:admin --elk-server 10.10.10.220 --smtp 10.10.10.90 --sender sender@gmail.com --to recipient@gmail.com  --dashboard "Basic Dashboard" --time 180 days</command>
      <interval>1w</interval>
      <ignore_output>yes</ignore_output>
      <run_on_start>yes</run_on_start>
      <timeout>300</timeout>
    </wodle>
  ```
  In this configuration, we assign an execution time of no more than 5 minutes (timeout=300) and an execution interval of one week, it means it will be a Weekly report.
<br>
</details>

<details>
<summary>Spanish Documentation</summary>
<br>
  
  ## Introducción

  Este script fue diseñado para extraer visualizaciones ya creadas en Kibana y plasmarlas en un correo electronico con formato HTML. Las visualizaciones soportadas hasta ahora son:

  - Tablas (Data Table, only configured with `Split Rows` and `Terms` as aggregations)
  - Graficos de torta (Pie, only configured with `Split Slices` and `Terms` as aggregations)
  - Graficos de barra o histogramas (Vertical Bar, only configured with `X-axis` and `Terms` as aggregations)

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
<br>
</details>
