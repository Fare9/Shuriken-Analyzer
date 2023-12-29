public class DexParserTest {

    private int field1;
    private String field2;

    public DexParserTest() {
        field1 = 42;
        field2 = "Hello, Dex Parser!";
    }

    public static void main(String[] args) {
        DexParserTest testInstance = new DexParserTest();
        testInstance.printMessage();
        testInstance.calculateSum(10, 20);
    }

    private void printMessage() {
        System.out.println("Field 1: " + field1);
        System.out.println("Field 2: " + field2);
        System.out.println("This is a test message printed from DexParserTest class.");
    }

    private int calculateSum(int a, int b) {
        int sum = a + b;
        System.out.println("Sum of " + a + " and " + b + " is: " + sum);
        return sum;
    }
}
