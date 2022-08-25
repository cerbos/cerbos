package demo;

import static dev.cerbos.sdk.builders.AttributeValue.boolValue;
import static dev.cerbos.sdk.builders.AttributeValue.stringValue;

import java.security.Principal;
import java.util.Map;

import dev.cerbos.sdk.CerbosBlockingClient;
import dev.cerbos.sdk.CerbosClientBuilder;
import dev.cerbos.sdk.CheckResult;
import dev.cerbos.sdk.builders.ResourceAction;


public class App {
    public static void main(String[] args) throws CerbosClientBuilder.InvalidClientConfigurationException {
        CerbosBlockingClient client=new CerbosClientBuilder("localhost:3593").withPlaintext().buildBlockingClient();

        for (String n : new String[]{"BUGS001", "DAFFY002"}) {
            CheckResult cr = client.batch(
                Principal.newInstance("bugs_bunny", "user")
                    .withAttribute("beta_tester", boolValue(true))
                )
                .addResources(
                    ResourceAction.newInstance("album:object","BUGS001")
                        .withAttributes(
                            Map.of(
                                "owner", stringValue("bugs_bunny"),
                                "public", boolValue(false),
                                "flagged", boolValue(false)
                            )
                        )
                        .withActions("view:public", "comment"),
                    ResourceAction.newInstance("album:object","DAFFY002")
                        .withAttributes(
                            Map.of(
                                "owner", stringValue("daffy_duck"),
                                "public", boolValue(true),
                                "flagged", boolValue(false)
                            )
                        )
                        .withActions("view:public", "comment")
                )
                .check().find(n).orElse(null);

            if (cr != null) {
                System.out.printf("\nResource: %s\n", n);
                cr.getAll().forEach((action, allowed) -> { System.out.printf("\t%s -> %s\n", action, allowed ? "EFFECT_ALLOW" : "EFFECT_DENY"); });
            }
        }
    }
}
