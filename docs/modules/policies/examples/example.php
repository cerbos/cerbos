<?php

require __DIR__ . '/vendor/autoload.php';

use Cerbos\Sdk\Builder\CerbosClientBuilder;
use Cerbos\Sdk\Builder\Principal;
use Cerbos\Sdk\Builder\ResourceAction;
use Symfony\Component\HttpClient\HttplugClient;

$clientBuilder = new CerbosClientBuilder("http://localhost:3592", new HttplugClient(), null, null, null);
$client = $clientBuilder->build();

$principal = Principal::newInstance("123")
              ->withRole("USER")
              ->withAttribute("workspaces", [
                  "workspaceA" => [
                      "role" => "OWNER"
                  ],
                  "workspaceB" => [
                      "role" => "MEMBER"
                  ]
              ]);

$type = "workspace";

$resourceAction1 = ResourceAction::newInstance($type, "workspaceA")
                    ->withAction("workspace:view")
                    ->withAction("pii:view");

$resourceAction2 = ResourceAction::newInstance($type, "workspaceB")
                    ->withAction("workspace:view")
                    ->withAction("pii:view");

$checkResourcesResult = $client->checkResources($principal, array($resourceAction1, $resourceAction2), null, null);

echo json_encode($checkResourcesResult, JSON_PRETTY_PRINT);

?>
