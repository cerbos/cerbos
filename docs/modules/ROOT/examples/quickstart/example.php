<?php

require __DIR__ . '/vendor/autoload.php';

use Cerbos\Effect\V1\Effect;
use Cerbos\Sdk\Builder\AttributeValue;
use Cerbos\Sdk\Builder\CerbosClientBuilder;
use Cerbos\Sdk\Builder\CheckResourcesRequest;
use Cerbos\Sdk\Builder\Principal;
use Cerbos\Sdk\Builder\ResourceEntry;
use Cerbos\Sdk\Utility\RequestId;

$client = CerbosClientBuilder::newInstance("localhost:3593")
            ->withPlaintext(true)
            ->build();

$request = CheckResourcesRequest::newInstance()
    ->withRequestId(RequestId::generate())
    ->withPrincipal(
        Principal::newInstance("bugs_bunny")
            ->withRole("user")
            ->withAttribute("beta_tester", AttributeValue::boolValue(true))
    )
    ->withResourceEntries(
        [
            ResourceEntry::newInstance("album:object", "BUGS001")
                ->withAttribute("owner", AttributeValue::stringValue("bugs_bunny"))
                ->withAttribute("public", AttributeValue::boolValue(false))
                ->withAttribute("flagged", AttributeValue::boolValue(false))
                ->withActions(["comment", "view:public"]),

            ResourceEntry::newInstance("album:object", "DAFFY002")
                ->withAttribute("owner", AttributeValue::stringValue("daffy_duck"))
                ->withAttribute("public", AttributeValue::boolValue(true))
                ->withAttribute("flagged", AttributeValue::boolValue(false))
                ->withActions(["comment", "view:public"])
        ]
    );

$checkResourcesResponse = $client->checkResources($request);
foreach (["BUGS001", "DAFFY002"] as $resourceId) {
    $resultEntry = $checkResourcesResponse->find($resourceId);
    $actions = $resultEntry->getActions();
    foreach ($actions as $k => $v) {
        printf("%s -> %s", $k, Effect::name($v));
    }
}
?>
