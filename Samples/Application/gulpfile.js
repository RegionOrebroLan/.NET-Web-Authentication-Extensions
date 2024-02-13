// /// <binding BeforeBuild="default" Clean="clean" ProjectOpened="watch" />
// If you want to bind to Visual Studio events, remove the leading "// " above.
"use strict";
{
	const del = require("del");
	const fileSystem = require("fs");
	const gulp = require("gulp");
	const path = require("path");
	const plumber = require("gulp-plumber");
	const rename = require("gulp-rename");
	const rollup = require("rollup");
	const rollupCommonJs = require("@rollup/plugin-commonjs");
	const rollupNodeResolver = require("@rollup/plugin-node-resolve");
	const rollupTerser = require("rollup-plugin-terser");
	const rollupTypescript = require("@rollup/plugin-typescript");
	const sass = require("gulp-sass")(require("node-sass"));
	const svgSrite = require("gulp-svg-sprite");
	const sourcemaps = require("gulp-sourcemaps");

	const destinationRootDirectoryName = "wwwroot";
	const iconsDirectoryName = "Icons";
	const imagesDirectoryName = "Images";
	const scriptsDirectoryName = "Scripts";
	const styleDirectoryName = "Style";
	
	const iconsSourceDirectory = path.join(styleDirectoryName, iconsDirectoryName);
	const imagesDestinationDirectory = path.join(destinationRootDirectoryName, styleDirectoryName, imagesDirectoryName);
	const imagesSourceDirectory = path.join(styleDirectoryName, imagesDirectoryName);
	const scriptsDestinationDirectory = path.join(destinationRootDirectoryName, scriptsDirectoryName);
	const scriptsSourceDirectory = scriptsDirectoryName;
	const spriteDestinationDirectory = path.join(destinationRootDirectoryName, styleDirectoryName, iconsDirectoryName);
	const styleDestinationDirectory = path.join(destinationRootDirectoryName, styleDirectoryName);
	const styleSourceDirectory = styleDirectoryName;

	async function buildScriptBundle() {
		console.log("Building script-bundle...");

		del(replaceBackSlashWithForwardSlash(path.join(scriptsDestinationDirectory, "**/*.js")));

		var bundleName = "Site.js";

		rollup.rollup(createRollupInputOptions()).then(bundle => {
			writeScriptBundle(bundle, path.join(scriptsDestinationDirectory, bundleName), true);
		});

		return rollup.rollup(createRollupInputOptions(true)).then(bundle => {
			return writeScriptBundle(bundle, path.join(scriptsDestinationDirectory, bundleName.replace(".", ".min.")));
		});
	}

	function buildSprite() {
		console.log("Building sprite...");

		deleteIfExists(spriteDestinationDirectory);

		const spriteFileName = "sprite.svg";
		
		return gulp.src(replaceBackSlashWithForwardSlash(path.join(iconsSourceDirectory, "**/*.svg")))
			.pipe(plumber())
			.pipe(svgSrite({
				mode: {
					symbol: {
						dest: "",
						render: false,
						sprite: spriteFileName
					}
				}
			}))
			.on("error",
				function(error) {
					if (!error)
						return;

					const errorMessage = error.message || error;

					log.error("Failed to compile sprite.", errorMessage.toString());
					this.emit("end");
				})
			.pipe(gulp.dest(spriteDestinationDirectory));
	}

	function buildStyleSheets() {
		console.log("Building style-sheets...");

		del(replaceBackSlashWithForwardSlash(path.join(styleDestinationDirectory, "**/*.css")));

		return gulp.src(replaceBackSlashWithForwardSlash(path.join(styleSourceDirectory, "Site.scss")))
			.pipe(sourcemaps.init())
			.pipe(sass(createSassOptions()).on("error", sass.logError))
			.pipe(sourcemaps.write())
			.pipe(gulp.dest(styleDestinationDirectory))
			.pipe(sass(createSassOptions(true)).on("error", sass.logError))
			.pipe(rename({ suffix: ".min" }))
			.pipe(gulp.dest(styleDestinationDirectory));
	}

	function clean(done) {
		const excludePattern = ".gitkeep";
		const pattern = "**/*";

		const scriptsExcludePattern = "!" + replaceBackSlashWithForwardSlash(path.join(scriptsDestinationDirectory, excludePattern));
		const scriptsPattern = replaceBackSlashWithForwardSlash(path.join(scriptsDestinationDirectory, pattern));
		console.log("Cleaning script-files...");
		del.sync([scriptsPattern, scriptsExcludePattern]);

		const styleExcludePattern = "!" + replaceBackSlashWithForwardSlash(path.join(styleDestinationDirectory, excludePattern));
		const stylePattern = replaceBackSlashWithForwardSlash(path.join(styleDestinationDirectory, pattern));
		console.log("Cleaning style-files...");
		del.sync([stylePattern, styleExcludePattern]);

		done();
	};

	function copyImages() {
		console.log("Copying images...");

		deleteIfExists(imagesDestinationDirectory);

		return gulp.src([path.join(imagesSourceDirectory, "**/*"), `!${path.join(imagesSourceDirectory, "ReadMe.md")}`])
			.pipe(gulp.dest(destinationRootDirectoryName));
	}

	function createRollupInputOptions(minify) {
		const plugins = [
			rollupNodeResolver.nodeResolve(),
			rollupCommonJs(),
			rollupTypescript()
		];

		if (minify) {
			plugins.push(rollupTerser.terser());
			//	plugins.push(rollupTerser.terser({
			//		output: {
			//			comments: "/^!/"
			//		}
			//	}));
		}

		return {
			input: path.join(scriptsSourceDirectory, "Site.ts"),
			plugins: plugins
		};
	}

	function createRollupOutputOptions(file, sourcemap) {
		const format = "iife";
		const name = "regionOrebroLan.identityServer";

		return {
			file: file,
			format: format,
			name: name,
			sourcemap: sourcemap ? "inline" : false
		};
	}

	function createSassOptions(compressed) {
		return {
			includePaths: ["node_modules"],
			indentType: "tab",
			indentWidth: 1,
			linefeed: "crlf",
			outputStyle: compressed ? "compressed" : "expanded"
		};
	}

	function deleteIfExists(pathToDelete)
	{
		if (fileSystem.existsSync(pathToDelete))
			del.sync(pathToDelete, {force: true});
	}

	function replaceBackSlashWithForwardSlash(value) {
		return value.replace(/\\/g, "/");
	}

	function watchIcons() {

		const patterns = [
			replaceBackSlashWithForwardSlash(path.join(iconsSourceDirectory, "**/*.svg"))
		];

		gulp.watch(patterns, buildSprite);
	}

	function watchImages() {

		const patterns = [
			replaceBackSlashWithForwardSlash(path.join(imagesSourceDirectory, "**/*"))
		];

		gulp.watch(patterns, copyImages);
	}

	function watchSass() {

		const patterns = [
			replaceBackSlashWithForwardSlash(path.join(styleSourceDirectory, "**/*.scss"))
		];

		gulp.watch(patterns, buildStyleSheets);
	}

	function watchScripts() {

		const patterns = [
			replaceBackSlashWithForwardSlash(path.join(scriptsSourceDirectory, "**/*.js")),
			replaceBackSlashWithForwardSlash(path.join(scriptsSourceDirectory, "**/*.ts"))
		]; 
		
		gulp.watch(patterns, buildScriptBundle);
	}

	async function writeScriptBundle(bundle, file, sourcemap) {
		return bundle.write(createRollupOutputOptions(file, sourcemap)).then(() => {
			return gulp.src(file)
				.pipe(rename(item => {
					item.dirname = "";
				}));
		});
	}

	gulp.task("build-script-bundle", buildScriptBundle);

	gulp.task("build-sprite", gulp.series(buildSprite, watchIcons));

	gulp.task("build-style-sheets", buildStyleSheets);

	gulp.task("clean", gulp.series(clean));
	
	gulp.task("copy-images", gulp.series(copyImages, watchImages));

	gulp.task("default", gulp.parallel(buildScriptBundle, buildSprite, buildStyleSheets, copyImages));

	gulp.task("watch", gulp.parallel(watchIcons, watchImages, watchSass, watchScripts));
}