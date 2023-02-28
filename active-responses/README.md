# Active Response Scripts

## remove-file-fim.cmd
This active response script receives a syscheck alert and deletes all files with the same hash in the detection folder.

## remove-file-vt.cmd
This active response script receives a VirusTotal alert and deletes all files with the same hash in the detection folder.

## remove-file-vt.cmd
This active response script is meant to be executed on-demand through an API call:
```
PUT /active-response?agents_list=<AGENT-ID>
{
  "command": "!remove-file-vt.cmd",
  "arguments": [<"add"> or <"delete">],
  "custom": true,
  "alert": {
    "id":"a-demanda"
  }
}
```
