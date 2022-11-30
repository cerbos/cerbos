package demo;

import static dev.cerbos.sdk.builders.AttributeValue.mapValue;
import static dev.cerbos.sdk.builders.AttributeValue.stringValue;

import java.util.Map;

import dev.cerbos.sdk.CerbosBlockingClient;
import dev.cerbos.sdk.CerbosClientBuilder;
import dev.cerbos.sdk.CheckResult;
import dev.cerbos.sdk.builders.Principal;
import dev.cerbos.sdk.builders.ResourceAction;


public class App {
    public static void main(String[] args) throws CerbosClientBuilder.InvalidClientConfigurationException {
        CerbosBlockingClient client=new CerbosClientBuilder("localhost:3593").withPlaintext().buildBlockingClient();

        for (String n : new String[]{"workspaceA", "workspaceB"}) {
            CheckResult cr = client.batch(
                Principal.newInstance("123", "USER")
                    .withAttribute("workspaces", mapValue(Map.of(
                        "workspaceA", mapValue(Map.of(
                                "role", stringValue("OWNER")
                        )),
                        "workspaceB", mapValue(Map.of(
                                "role", stringValue("MEMBER")
                        ))
                    )))
                )
                .addResources(
                    ResourceAction.newInstance("workspace","workspaceA")
                        .withActions("workspace:view", "pii:view"),
                    ResourceAction.newInstance("workspace","workspaceB")
                        .withActions("workspace:view", "pii:view")
                )
                .check().find(n).orElse(null);

            if (cr != null) {
                System.out.printf("\nResource: %s\n", n);
                cr.getAll().forEach((action, allowed) -> { System.out.printf("\t%s -> %s\n", action, allowed ? "EFFECT_ALLOW" : "EFFECT_DENY"); });
            }
        }
    }
}
