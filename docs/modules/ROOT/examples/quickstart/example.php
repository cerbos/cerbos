<?php

require __DIR__ . '/vendor/autoload.php';

use Cerbos\Sdk\Builder\CerbosClientBuilder;
use Cerbos\Sdk\Builder\Principal;
use Cerbos\Sdk\Builder\ResourceAction;
use Symfony\Component\HttpClient\HttplugClient;

$clientBuilder = new CerbosClientBuilder("http://localhost:3592", new HttplugClient(), null, null, null);
$client = $clientBuilder->build();

$principal = Principal::newInstance("bugs_bunny")
              ->withRole("user")
              ->withAttribute("beta_tester", true);

$resourceAction1 = ResourceAction::newInstance("album:object", "BUGS001")
                    ->withAction("view:public")
                    ->withAction("comment")
                    ->withAttribute("owner", "bugs_bunny")
                    ->withAttribute("public", false)
                    ->withAttribute("flagged", false);

$resourceAction2 = ResourceAction::newInstance("album:object", "DAFFY002")
                    ->withAction("view:public")
                    ->withAction("comment")
                    ->withAttribute("owner", "daffy_duck")
                    ->withAttribute("public", true)
                    ->withAttribute("flagged", false);

$checkResourcesResult = $client->checkResources($principal, array($resourceAction1, $resourceAction2), null, null);

echo json_encode($checkResourcesResult, JSON_PRETTY_PRINT);

?>
