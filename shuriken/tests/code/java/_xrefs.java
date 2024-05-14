package com.dexbox;

public class _xrefs {

    public class _xrefs_internals {
        // Field with cross-references
        public final int FieldFinalInt = 4;
        public int FieldInt;

        // Method with cross-references
        public void Method1(int a) {
            System.out.println("Setting FieldInt"); // Cross-reference to FieldInt
            FieldInt = a;
            System.out.println("FieldInt set"); // Cross-reference to FieldInt
        }

        // Method with internal strings
        public void Method2() {
            String internalString = "This is an internal string"; // Internal string
            System.out.println(internalString); // Cross-reference to internalString
        }
    }

    private _xrefs_internals internalsInstance = new _xrefs_internals(); // Instance of the internal class

    // Method in the outer class calling a method in the internal class
    public void callInternalMethod() {
        internalsInstance.Method1(10); // Call Method1 from the outer class
    }

    // Method in the outer class accessing a field in the internal class
    public void accessInternalField() {
        System.out.println("Value of FieldFinalInt: " + internalsInstance.FieldFinalInt); // Access FieldFinalInt from the outer class
    }

    // Method in the outer class calling another method in the internal class
    public void callInternalMethod2() {
        internalsInstance.Method2(); // Call Method2 from the outer class
    }
}
