/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.matilda.bootstrap;

import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;




/**
 * The Matilda AccessController allows granting permissions per module via System.properties()
 * permissions can be passed using the following format
 * "matilda.<function>.allow=<Modul that should be allowed>"
 * Example: -Dmatilda.system.exit.allow=module gradle.worker
 */
// Class is final for security purpose, to supress any manipulation
public final class MatildaAccessControl {
    // TODO: replace the Allowed modules with a simple check for "java.base"
    // TODO: Fix, potential circular dependency
    private static final Set<Module> ALLOWED_MODULES = Set.of(System.class.getModule());
    private static final MatildaAccessControl INSTANCE = new MatildaAccessControl(System.getProperties());
    private final Set<String> systemExitAllowPermissions;
    private final Set<String> systemExecAllowPermissions;
    private final Set<String> networkConnectAllowPermissions;
    static Logger logger;

    // TODO document that this returns a singleton instance of the access control. ie. simple singleton pattern
    public static MatildaAccessControl getInstance() {
        return INSTANCE;
    }

    /**
     * Instantiates properties that can be set over the commandline
     * @param properties - Properties should be passed via System.properties => matilda.system.exit.allow=Module that should be allowed
     */
    public MatildaAccessControl(Properties properties) {

        // TODO iterate over all the keys and see if there is any of them that we don't know that starts with matilda
        // if so throw an exception -- also write a test for it
        String systemExistAllow = properties.getProperty("matilda.system.exit.allow", "");
        String systemExecAllow = properties.getProperty("matilda.system.exec.allow", "");
        String networkConnectAllow = properties.getProperty("matilda.network.connect.allow", "");
        this.systemExitAllowPermissions = Set.of(systemExistAllow.split(","));
        this.systemExecAllowPermissions = Set.of(systemExecAllow.split(","));
        this.networkConnectAllowPermissions = Set.of(networkConnectAllow.split(","));
    }


    /**
     * Is called by method that is instrumented by the agent, this is necessary to get the correct call stack
     * @param method - method that should be checked for permissions
     */
    public static void checkPermission(String method) {
        // this is an indirection to simplify the code generated in the agent
        INSTANCE.checkPermissionInternal(method);
    }

    /**
     * Method checks if called method has the permissions to be executed
     * @param method - method that is currently called
     * @throws RuntimeException - if method/ callers don't have the permissions to be executed
     */
    // should be private
    public void checkPermissionInternal(String method) {
        switch (method) {
            case "System.exit":
                if (!checkSystemExit()) throw new RuntimeException("System.exit not allowed");
                else return;
            case "ProcessBuilder.start":
                if (!checkSystemExec()) throw new RuntimeException("ProceesBuilder.start(...) not allowed");
                else return;
            case "Socket.connect":
                if (!checkSocketPermission()) throw new RuntimeException("Socket.connect not allowed");
                else return;
            default:
                throw new IllegalArgumentException("Unknown method: " + method);
        }
    }

    /**
     * Checks if caller has permission to call System.exit()
     * @return boolean - true iff caller module has the right permissions otherwise false
     * @see #callingClassModule() for reference how the caller module is identified
     */
    private boolean checkSystemExit() {
        var callingClass = callingClassModule();
        logger = Logger.getLogger(MatildaAccessControl.class.getName());
        // TODO message should say module and should reflect that we are checking. also include the return value of the permission checking
        logger.log(Level.FINE, "Class that initially called the method " + callingClass.toString());
        return this.systemExitAllowPermissions.contains(callingClass.toString());
    }

    /**
     * Checks if caller has permission to call System.exec()
     *@return boolean - true iff caller module has the right permissions otherwise false
     *@see #callingClassModule() for reference how the caller module is identified
     */
    private boolean checkSystemExec() {
        var callingClass = callingClassModule();
        logger = Logger.getLogger(MatildaAccessControl.class.getName());
        // TODO message should say module and should reflect that we are checking. also include the return value of the permission checking
        logger.log(Level.FINE, "Class that initially called the method " + callingClass.toString());
        return this.systemExecAllowPermissions.contains(callingClass.toString());
    }


    /**
     * Checks if caller has permission to call Socket.connect()
     *@return boolean - true iff caller module has the right permissions otherwise false
     *@see #callingClassModule() for reference how the caller module is identified
     */
    private boolean checkSocketPermission() {
        var callingClass = callingClassModule();
        logger = Logger.getLogger(MatildaAccessControl.class.getName());
        // TODO message should say module and should reflect that we are checking. also include the return value of the permission checking
        logger.log(Level.FINE, "Class that initially called the method {0} ", callingClass);
        return this.networkConnectAllowPermissions.contains(callingClass.toString());
    }

    /**
     * In order to identify the caller skipframes of the helper methods as well as the called method needs to be skipped
     * needs to be adapted if structure of the AccessContoller changes
     * @return Module - Returns module that initially called method
     */
    private Module callingClassModule() {
        final int framesToSkip = 1  // getCallingClass (this method)
                + 1  // the checkXxx method
                + 1  // Instantiation
                + 1  // the runtime config method
                + 1  // the instrumented method
                ;
        return callingClass(framesToSkip);
    }


    /**
     * Iterates over the current Stack and skips specified number of elements
     * @param framesToSkip - number of frames, element on stack that should be skipped
     * @return Module - calling Module
     */
    //TODO make private, is just public for testing purposes
    public Module callingClass(int framesToSkip) {
        if (framesToSkip < 0) throw new IllegalArgumentException("framesToSkip must be >=0");
        Optional<Module> module = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(
                        s -> s.skip(framesToSkip)
                                .map(f -> {
                                    Class<?> declaringClass = f.getDeclaringClass();
                                    return declaringClass.getModule();
                                })
                                .filter(m -> !ALLOWED_MODULES.contains(m))
                                .findFirst()
                );
        return module.orElse(null);
    }

}
