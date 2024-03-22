using Cerbos.Api.V1.Effect;
using Cerbos.Sdk.Response;
using Cerbos.Sdk.Builder;
using Cerbos.Sdk.Utility;

internal class Program
{
    private static void Main(string[] args)
    {
        var client = CerbosClientBuilder.ForTarget("http://localhost:3593").WithPlaintext().Build();
        var request = CheckResourcesRequest
            .NewInstance()
            .WithRequestId(RequestId.Generate())
            .WithIncludeMeta(true)
            .WithPrincipal(
                Principal
                    .NewInstance("bugs_bunny", "user")
                    .WithAttribute("beta_tester", AttributeValue.BoolValue(true))
            )
            .WithResourceEntries(
                ResourceEntry
                    .NewInstance("album:object", "BUGS001")
                    .WithAttribute("owner", AttributeValue.StringValue("bugs_bunny"))
                    .WithAttribute("public", AttributeValue.BoolValue(false))
                    .WithAttribute("flagged", AttributeValue.BoolValue(false))
                    .WithActions("comment", "view:public"),

                ResourceEntry
                    .NewInstance("album:object", "DAFFY002")
                    .WithAttribute("owner", AttributeValue.StringValue("daffy_duck"))
                    .WithAttribute("public", AttributeValue.BoolValue(true))
                    .WithAttribute("flagged", AttributeValue.BoolValue(false))
                    .WithActions("comment", "view:public")
            );

        CheckResourcesResponse result = client.CheckResources(request);
        foreach (var resourceId in new[] { "BUGS001", "DAFFY002" })
        {
            var resultEntry = result.Find(resourceId);
            Console.Write($"\nResource ID: {resourceId}\n");
            foreach (var actionEffect in resultEntry.Actions)
            {
                string action = actionEffect.Key;
                Effect effect = actionEffect.Value;
                Console.Write($"\t{action} -> {(effect == Effect.Allow ? "EFFECT_ALLOW" : "EFFECT_DENY")}\n");
            }
        }
    }
}
