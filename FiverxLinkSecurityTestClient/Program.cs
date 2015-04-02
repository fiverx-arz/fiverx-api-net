


namespace FiverxLinkSecurityTestClient
{
  class Program
  {
    static void Main(string[] args)
    {
      Demolauf();
    }

    private static void Demolauf()
    {
      /*Zum Testen entsprechende Methoden einkommentieren bzw. auskommentieren!*/

      //Zertifikaterstellung:

      //Demo.DemoServerZertifikat(true);
      //Demo.DemoClientZertifikat();

      //Lokale Demoausführungen:

      //Demo.DemoRzeAnfrage();
      //Demo.DemoRzeAntwort();

      //Serviceanfragen:

      Demo.DemoServiceAnfrageVerarbeiteAuftrag();
      //Demo.DemoServiceAnfrageLadeRzSecurityVersion();
      //Demo.DemoTestAnfrageNARZTestservice();
    }


  }
}
