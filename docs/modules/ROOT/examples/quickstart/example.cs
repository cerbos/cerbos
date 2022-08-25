using Cerbos.Sdk.Builders;
using Cerbos.Sdk;

internal class Program
{
    private static void Main(string[] args)
    {
        var client = new CerbosClientBuilder("http://localhost:3593").WithPlaintext().BuildBlockingClient();
        string[] actions = { "view:public", "comment" };

        CheckResourcesResult result = client
            .CheckResources(
                Principal.NewInstance("bugs_bunny", "user")
                    .WithAttribute("beta_tester", AttributeValue.BoolValue(true)),

                ResourceAction.NewInstance("album:object", "BUGS001")
                    .WithAttribute("owner", AttributeValue.StringValue("bugs_bunny"))
                    .WithAttribute("public", AttributeValue.BoolValue(false))
                    .WithAttribute("flagged", AttributeValue.BoolValue(false))
                    .WithActions(actions),

                ResourceAction.NewInstance("album:object", "DAFFY002")
                    .WithAttribute("owner", AttributeValue.StringValue("daffy_duck"))
                    .WithAttribute("public", AttributeValue.BoolValue(true))
                    .WithAttribute("flagged", AttributeValue.BoolValue(false))
                    .WithActions(actions)
            );

        foreach (string n in new string[] { "BUGS001", "DAFFY002" })
        {
            var r = result.Find(n);
            Console.Write(String.Format("\nResource: {0}\n", n));
            foreach (var i in r.GetAll())
            {
                String action = i.Key;
                Boolean isAllowed = i.Value;
                Console.Write(String.Format("\t{0} -> {1}\n", action, isAllowed ? "EFFECT_ALLOW" : "EFFECT_DENY"));
            }
        }
    }
}
