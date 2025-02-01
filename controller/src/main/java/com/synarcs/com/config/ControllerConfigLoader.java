package com.synarcs.com.config;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import com.synarcs.com.config.yaml.Config;

public class ControllerConfigLoader implements Serializable {
    Logger logger = LoggerFactory.getLogger(ControllerConfigLoader.class);
    
    public Config loadControllerConfig() throws IOException {
        Yaml yaml = new Yaml(new Constructor(Config.class, new LoaderOptions()));
        InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream("config.yaml");
        if (inputStream == null) {
            throw new IOException("config.yaml file not found in classpath!");
        }
        Config config = yaml.load(inputStream);
        inputStream.close();
        return config;
    }
}
