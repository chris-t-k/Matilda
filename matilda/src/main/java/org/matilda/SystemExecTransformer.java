/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.matilda;

import java.lang.classfile.CodeTransform;
import java.lang.classfile.MethodModel;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;


/**
 * Custom transformer that allows granular blocking of System.exec() which is triggered by Runtime.getRuntime().exec(...)
 */
@SuppressWarnings("preview")
public class SystemExecTransformer implements MatildaCodeTransformer {
    // Boolean indicates if a transformation has been run
    private final AtomicBoolean hasRun = new AtomicBoolean(false);

    /**
     * Transforms a class that test positive for the TransformPredicate*
     */
    @Override
    public CodeTransform getTransform() {
        return (codeBuilder, codeElement) -> {
            // checks if codeELement needs to be transformed
            if (!hasRun.getAndSet(true)) { // this must only be run / added once on top of the method
                var accessControl = ClassDesc.of("org.matilda.bootstrap.MatildaAccessControl");
                // method descriptor is set V indicates that the method returns no value
                var methodTypeDesc = MethodTypeDesc.ofDescriptor("(Ljava/lang/String;)V");
                codeBuilder
                        // Needs to be hard coded in order to not run into classpath issues when using MatildaAccessControl, as it is not loaded yet
                        .ldc("ProcessBuilder.start")
                        .invokestatic(accessControl, "checkPermission", methodTypeDesc)
                        .with(codeElement);
            } else {
                codeBuilder.with(codeElement);
            }
        };
    }

    /**
     * Matches MethodeElement against characteristics specific to the java.net.System exec and returns true accordingly
     * MethoModel models a method and can be traversed with a stream
     *
     * @return Predicate - Holds structure of method that should be transformed
     * Gets the method owner/ class method is an element of
     * as we are looking for methods owned by "java/lang/ProcessBuilder" we check for the owner
     * check if method that is called is the connect method
     * check if method has the correct method descriptor
     */
    @Override
    public Predicate<MethodModel> getModelPredicate() {
        return methodElements -> {
            // Get class method is an element of
            String internalName = methodElements.parent().get().thisClass().asInternalName();
            // Check if its parent is the ProcessBuilder Class
            return internalName.equals("java/lang/ProcessBuilder")
                    // Matches Methode
                    && "start".equals(methodElements.methodName().stringValue())
                    // Matches Methode Type
                    && "([Ljava/lang/ProcessBuilder$Redirect;)Ljava/lang/Process;".equals(methodElements.methodType().stringValue());
        };
    }
}
