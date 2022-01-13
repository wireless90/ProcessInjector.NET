using System;

namespace DllHijacking
{
    class Program
    {
        static void Main(string[] args)
        {
            Person person = new Person("Razali");
            Person clonedPerson = ObjectCloner.ObjectCloner.DeepClone(person);

            Console.WriteLine($"{person.Name}={clonedPerson.Name}");

            Console.ReadKey(true);
        }
    }

    public class Person
    {
        public Person(string name)
        {
            Name = name;
        }
        public string Name { get; set; }
    }
}
