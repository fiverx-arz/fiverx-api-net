﻿


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
      //Demo.DemoServerZertifikat(true);
      //Demo.DemoClientZertifikat();
      Demo.DemoServiceAnfrage();
      Demo.DemoServiceAntwort();

    }
  }
}