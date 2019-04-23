module.exports = function(grunt) {

  grunt.initConfig({

    watch: {
      js: {
        files: ['lib/**/*.js'],
        tasks: ['concat:lib', 'babel', 'concat:vendor', 'concat:dist', 'concat:regenerator', 'browserify'],
        options: {
          spawn: false,
        },
      },
    },

    concat: {
      options: {
        separator: ';',
      },

      lib: {
        src: [
          'lib/**/*.js',
        ],
        dest: 'dist/lib.js',
      },

      vendor: {
        src: [
          'vendor/cryptojs/*.js'

        ],
        dest: 'dist/vendor.js',
      },

      regenerator: {
        src: ['node_modules/regenerator-runtime/runtime.js'],
        dest: 'dist/regenerator.js'
      },

      lodash: {
        src: ['vendor/lodash/lodash.custom.min.js'],
        dest: 'dist/lodash.min.js'
      },

      dist: {
        src: ['dist/vendor.js', 'dist/transpiled.js'],
        dest: 'dist/sfjs.js',
      },
    },

    babel: {
      options: {
        sourceMap: true,
      },

      dist: {
        files: {
          'dist/transpiled.js': 'dist/lib.js'
        }
      },
    },

    browserify: {

      dist: {
        options: {
          browserifyOptions: {
            standalone: 'SF',
          }
        },
        files: {
          'dist/sfjs.js': 'dist/sfjs.js'
        }
      },
    },

     uglify: {
       compiled: {
         src: ['dist/regenerator.js', 'dist/sfjs.js'],
         dest: 'dist/sfjs.min.js'
       }
    }
  });

  grunt.loadNpmTasks('grunt-newer');
  grunt.loadNpmTasks('grunt-contrib-watch');
  grunt.loadNpmTasks('grunt-contrib-uglify');
  grunt.loadNpmTasks('grunt-babel');
  grunt.loadNpmTasks('grunt-browserify');
  grunt.loadNpmTasks('grunt-contrib-concat');

  grunt.registerTask('default', ['concat:lib', 'babel', 'concat:lodash', 'concat:vendor', 'concat:dist', 'concat:regenerator', 'browserify']);
  grunt.registerTask('minify', ['uglify']);
};
